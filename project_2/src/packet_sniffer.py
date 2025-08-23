"""
Network Packet Sniffer with Anomaly Detection
Real-time network traffic monitoring with alert system
"""

import time
import sqlite3
import smtplib
import threading
import logging
import platform
import sys
import os
from collections import defaultdict, deque
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
except ImportError:
    print("Error: Scapy not installed!")
    print("Install with: pip install scapy")
    if platform.system() == "Windows":
        print("Windows users also need Npcap: https://npcap.com/")
    sys.exit(1)

class DatabaseManager:
    """Handles all database operations for packet storage and retrieval"""
    
    def __init__(self, db_path="network_monitor.db"):
        self.db_path = db_path
        self.connection = None
        self.lock = threading.Lock()
        self.init_database()
        
    def init_database(self):
        """Initialize the database connection"""
        try:
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA synchronous=NORMAL")
            
            # Verify tables exist
            cursor = self.connection.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='packets'")
            if not cursor.fetchone():
                print("Database not initialized! Run db_init.py first.")
                sys.exit(1)
                
            print(f"Database connected: {self.db_path}")
            
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            sys.exit(1)
            
    def log_packet(self, src_ip, dst_ip, src_port, dst_port, protocol, length, flags, data):
        """Log a captured packet to database"""
        try:
            with self.lock:
                cursor = self.connection.cursor()
                cursor.execute("""
                    INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol, packet_length, flags, packet_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (src_ip, dst_ip, src_port, dst_port, protocol, length, flags, data))
                self.connection.commit()
        except sqlite3.Error as e:
            logging.error(f"Failed to log packet: {e}")
            
    def log_alert(self, alert_type, source_ip, description, severity="MEDIUM", target_ip=None):
        """Log security alert to database"""
        try:
            with self.lock:
                cursor = self.connection.cursor()
                cursor.execute("""
                    INSERT INTO alerts (alert_type, source_ip, target_ip, description, severity)
                    VALUES (?, ?, ?, ?, ?)
                """, (alert_type, source_ip, target_ip, description, severity))
                self.connection.commit()
        except sqlite3.Error as e:
            logging.error(f"Failed to log alert: {e}")
            
    def get_traffic_summary(self, minutes=60):
        """Get traffic summary for the last N minutes"""
        try:
            with self.lock:
                cursor = self.connection.cursor()
                since = datetime.now() - timedelta(minutes=minutes)
                cursor.execute("""
                    SELECT protocol, COUNT(*) as packet_count, SUM(packet_length) as total_bytes,
                           COUNT(DISTINCT src_ip) as unique_src_ips
                    FROM packets 
                    WHERE timestamp > ? 
                    GROUP BY protocol
                    ORDER BY packet_count DESC
                """, (since,))
                return cursor.fetchall()
        except sqlite3.Error as e:
            logging.error(f"Failed to get traffic summary: {e}")
            return []
    
    def cleanup_old_data(self, days=30):
        """Clean up old packet data"""
        try:
            with self.lock:
                cursor = self.connection.cursor()
                cutoff = datetime.now() - timedelta(days=days)
                cursor.execute("DELETE FROM packets WHERE timestamp < ?", (cutoff,))
                deleted = cursor.rowcount
                self.connection.commit()
                return deleted
        except sqlite3.Error as e:
            logging.error(f"Failed to cleanup data: {e}")
            return 0

class AnomalyDetector:
    """Detect network anomalies and suspicious activities"""
    
    def __init__(self, db_manager, alert_callback=None):
        self.db_manager = db_manager
        self.alert_callback = alert_callback
        self.packet_counts = defaultdict(int)
        self.port_scan_tracker = defaultdict(set)
        self.flood_tracker = defaultdict(deque)
        self.packet_size_tracker = defaultdict(deque)
        self.syn_flood_tracker = defaultdict(deque)
        
        # Load thresholds from config or use defaults
        self.load_thresholds()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self.periodic_cleanup, daemon=True)
        self.cleanup_thread.start()
        
    def load_thresholds(self):
        """Load detection thresholds from database config"""
        try:
            cursor = self.db_manager.connection.cursor()
            cursor.execute("SELECT key, value FROM config")
            config = dict(cursor.fetchall())
            
            self.PORT_SCAN_THRESHOLD = int(config.get('port_scan_threshold', 20))
            self.FLOOD_THRESHOLD = int(config.get('flood_threshold', 100))
            self.LARGE_PACKET_THRESHOLD = int(config.get('large_packet_threshold', 1500))
            self.TIME_WINDOW = int(config.get('time_window', 60))
        except:
            # Default values if config not available
            self.PORT_SCAN_THRESHOLD = 20
            self.FLOOD_THRESHOLD = 100
            self.LARGE_PACKET_THRESHOLD = 1500
            self.TIME_WINDOW = 60
            
    def analyze_packet(self, packet):
        """Analyze a packet for anomalies"""
        current_time = time.time()
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_size = len(packet)
            
            # Check for large packets
            if packet_size > self.LARGE_PACKET_THRESHOLD:
                self._trigger_alert("LARGE_PACKET", src_ip, 
                                  f"Unusually large packet: {packet_size} bytes", "LOW", dst_ip)
            
            # Track packet flooding
            self.flood_tracker[src_ip].append(current_time)
            self._cleanup_old_entries(self.flood_tracker[src_ip], current_time)
            
            if len(self.flood_tracker[src_ip]) > self.FLOOD_THRESHOLD:
                self._trigger_alert("PACKET_FLOOD", src_ip,
                                  f"Possible flooding: {len(self.flood_tracker[src_ip])} packets/minute", 
                                  "HIGH", dst_ip)
            
            # Port scan detection
            if TCP in packet:
                dst_port = packet[TCP].dport
                self.port_scan_tracker[src_ip].add(dst_port)
                
                if len(self.port_scan_tracker[src_ip]) > self.PORT_SCAN_THRESHOLD:
                    self._trigger_alert("PORT_SCAN", src_ip,
                                      f"Possible port scan: {len(self.port_scan_tracker[src_ip])} ports targeted", 
                                      "HIGH", dst_ip)
                
                # SYN flood detection
                if packet[TCP].flags & 0x02:  # SYN flag
                    self.syn_flood_tracker[dst_ip].append(current_time)
                    self._cleanup_old_entries(self.syn_flood_tracker[dst_ip], current_time)
                    
                    if len(self.syn_flood_tracker[dst_ip]) > self.FLOOD_THRESHOLD:
                        self._trigger_alert("SYN_FLOOD", src_ip,
                                          f"Possible SYN flood attack on {dst_ip}: {len(self.syn_flood_tracker[dst_ip])} SYN packets/minute",
                                          "CRITICAL", dst_ip)
            
            # Track packet sizes for statistical anomaly detection
            self.packet_size_tracker[src_ip].append(packet_size)
            if len(self.packet_size_tracker[src_ip]) > 100:
                self.packet_size_tracker[src_ip].popleft()
                
            # Statistical anomaly detection
            if len(self.packet_size_tracker[src_ip]) > 50:
                sizes = list(self.packet_size_tracker[src_ip])
                avg_size = sum(sizes) / len(sizes)
                if packet_size > avg_size * 3:  # 3x larger than average
                    self._trigger_alert("SIZE_ANOMALY", src_ip,
                                      f"Packet size anomaly: {packet_size} vs avg {avg_size:.2f}", 
                                      "MEDIUM", dst_ip)
    
    def _cleanup_old_entries(self, deque_obj, current_time):
        """Remove entries older than time window"""
        while deque_obj and current_time - deque_obj[0] > self.TIME_WINDOW:
            deque_obj.popleft()
    
    def periodic_cleanup(self):
        """Periodic cleanup of tracking data"""
        while True:
            time.sleep(300)  # Clean up every 5 minutes
            current_time = time.time()
            
            # Clean up port scan tracking
            for ip in list(self.port_scan_tracker.keys()):
                if len(self.port_scan_tracker[ip]) == 0:
                    del self.port_scan_tracker[ip]
            
            # Clean up flood tracking
            for ip in list(self.flood_tracker.keys()):
                self._cleanup_old_entries(self.flood_tracker[ip], current_time)
                if len(self.flood_tracker[ip]) == 0:
                    del self.flood_tracker[ip]
    
    def _trigger_alert(self, alert_type, source_ip, description, severity, target_ip=None):
        """Trigger an alert and log it"""
        self.db_manager.log_alert(alert_type, source_ip, description, severity, target_ip)
        if self.alert_callback:
            self.alert_callback(alert_type, source_ip, description, severity, target_ip)

class EmailAlerter:
    """Handle email notifications for alerts"""
    
    def __init__(self, smtp_server, smtp_port, username, password, recipients):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.recipients = recipients if isinstance(recipients, list) else [recipients]
        self.last_alert_time = defaultdict(float)
        self.alert_cooldown = 300  # 5 minutes cooldown per alert type
        
    def send_alert(self, alert_type, source_ip, description, severity, target_ip=None):
        """Send email alert with cooldown to prevent spam"""
        current_time = time.time()
        cooldown_key = f"{alert_type}_{source_ip}"
        
        # Check cooldown
        if current_time - self.last_alert_time[cooldown_key] < self.alert_cooldown:
            return
            
        try:
            msg = MIMEMultipart()
            msg['From'] = self.username
            msg['To'] = ', '.join(self.recipients)
            msg['Subject'] = f"🚨 Network Security Alert: {alert_type} - {severity}"
            
            body = f"""
🔴 NETWORK SECURITY ALERT 🔴

Alert Type: {alert_type}
Source IP: {source_ip}
Target IP: {target_ip or 'N/A'}
Severity: {severity}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Description: {description}

This is an automated alert from your network monitoring system.
Please investigate this potential security issue immediately.

System: Network Packet Sniffer v1.0
            """.strip()
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.username, self.password)
            text = msg.as_string()
            server.sendmail(self.username, self.recipients, text)
            server.quit()
            
            self.last_alert_time[cooldown_key] = current_time
            logging.info(f"Email alert sent for {alert_type} from {source_ip}")
            
        except Exception as e:
            logging.error(f"Failed to send email alert: {e}")

class PacketSniffer:
    """Main packet sniffer class"""
    
    def __init__(self, interface=None, config_file="config.json"):
        self.interface = self._detect_interface(interface)
        self.running = False
        self.packet_count = 0
        self.start_time = None
        self.session_id = None
        
        # Load configuration
        self.config = self.load_config(config_file)
        
        # Initialize components
        self.db_manager = DatabaseManager(self.config.get('database_path', 'network_monitor.db'))
        
        # Setup email alerter if configured
        email_config = self.config.get('email')
        if email_config and email_config.get('enabled', False):
            self.email_alerter = EmailAlerter(
                email_config['smtp_server'],
                email_config['smtp_port'],
                email_config['username'],
                email_config['password'],
                email_config['recipients']
            )
        else:
            self.email_alerter = None
            
        # Setup anomaly detector
        self.anomaly_detector = AnomalyDetector(
            self.db_manager,
            self._alert_callback if self.email_alerter else self._console_alert_callback
        )
        
        # Setup logging
        self._setup_logging()
        
    def _detect_interface(self, interface):
        """Detect available network interface"""
        if interface:
            return interface
            
        try:
            if platform.system() == "Windows":
                interfaces = get_if_list()
                # Filter out loopback
                real_interfaces = [iface for iface in interfaces if not iface.startswith("Loopback")]
                if real_interfaces:
                    selected = real_interfaces[0]
                    print(f"Windows: Auto-selected interface {selected}")
                    return selected
            return None
        except:
            return None
            
    def _setup_logging(self):
        """Setup logging configuration"""
        log_level = getattr(logging, self.config.get('logging', {}).get('level', 'INFO'))
        log_file = self.config.get('logging', {}).get('file', 'sniffer.log')
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
    def load_config(self, config_file):
        """Load configuration from JSON file"""
        default_config = {
            "database_path": "network_monitor.db",
            "interface": None,
            "email": {
                "enabled": False,
                "smtp_server": "smtp.gmail.com",
                "smtp_port": 587,
                "username": "your_email@gmail.com",
                "password": "your_app_password",
                "recipients": ["admin@company.com"]
            },
            "logging": {
                "level": "INFO",
                "file": "sniffer.log"
            }
        }
        
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
            else:
                # Create default config file
                with open(config_file, 'w') as f:
                    json.dump(default_config, f, indent=4)
                print(f"Created default config file: {config_file}")
                return default_config
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading config: {e}")
            return default_config
    
    def _alert_callback(self, alert_type, source_ip, description, severity, target_ip=None):
        """Callback for handling alerts with email"""
        self._console_alert_callback(alert_type, source_ip, description, severity, target_ip)
        if self.email_alerter:
            # Send email in separate thread to avoid blocking
            threading.Thread(
                target=self.email_alerter.send_alert,
                args=(alert_type, source_ip, description, severity, target_ip),
                daemon=True
            ).start()
    
    def _console_alert_callback(self, alert_type, source_ip, description, severity, target_ip=None):
        """Console alert callback"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        target_info = f" -> {target_ip}" if target_ip else ""
        print(f"🚨 [{timestamp}] {severity} ALERT: {alert_type}")
        print(f"   Source: {source_ip}{target_info}")
        print(f"   {description}")
        print("-" * 60)
    
    def start_session(self):
        """Start a new monitoring session"""
        try:
            cursor = self.db_manager.connection.cursor()
            cursor.execute("""
                INSERT INTO sessions (interface, status)
                VALUES (?, 'ACTIVE')
            """, (self.interface,))
            self.session_id = cursor.lastrowid
            self.db_manager.connection.commit()
        except sqlite3.Error as e:
            logging.error(f"Failed to start session: {e}")
    
    def end_session(self):
        """End the current monitoring session"""
        if self.session_id:
            try:
                duration = time.time() - self.start_time if self.start_time else 0
                cursor = self.db_manager.connection.cursor()
                cursor.execute("""
                    UPDATE sessions 
                    SET end_time = CURRENT_TIMESTAMP, 
                        total_packets = ?,
                        status = 'COMPLETED'
                    WHERE id = ?
                """, (self.packet_count, self.session_id))
                self.db_manager.connection.commit()
            except sqlite3.Error as e:
                logging.error(f"Failed to end session: {e}")
    
    def packet_handler(self, packet):
        """Process each captured packet"""
        if not self.running:
            return
            
        self.packet_count += 1
        
        try:
            # Extract packet information
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                packet_length = len(packet)
                
                # Determine protocol name and ports
                src_port = dst_port = None
                flags = ""
                
                if TCP in packet:
                    protocol_name = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    flags = str(packet[TCP].flags)
                elif UDP in packet:
                    protocol_name = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif ICMP in packet:
                    protocol_name = "ICMP"
                else:
                    protocol_name = f"IP_PROTO_{protocol}"
                
                # Log to database (store first 200 bytes of packet data)
                packet_data = bytes(packet)[:200] if len(packet) > 200 else bytes(packet)
                self.db_manager.log_packet(
                    src_ip, dst_ip, src_port, dst_port,
                    protocol_name, packet_length, flags,
                    packet_data
                )
                
                # Analyze for anomalies
                self.anomaly_detector.analyze_packet(packet)
                
                # Print packet info periodically
                if self.packet_count % 100 == 0:
                    elapsed = time.time() - self.start_time
                    rate = self.packet_count / elapsed if elapsed > 0 else 0
                    print(f"[{self.packet_count:6d}] {src_ip:15s}:{src_port or 0:5d} -> {dst_ip:15s}:{dst_port or 0:5d} "
                          f"({protocol_name:4s}) {packet_length:4d}B | {rate:.1f} pps")
                    
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
    
    def start_sniffing(self, packet_count=0, timeout=None):
        """Start packet capture"""
        print("=" * 80)
        print("🔍 NETWORK PACKET SNIFFER STARTING")
        print("=" * 80)
        print(f"Interface: {self.interface or 'All available'}")
        print(f"Database: {self.db_manager.db_path}")
        print(f"Email alerts: {'✅ Enabled' if self.email_alerter else '❌ Disabled'}")
        print(f"Platform: {platform.system()} {platform.release()}")
        print(f"Packet limit: {packet_count if packet_count > 0 else 'Unlimited'}")
        print(f"Timeout: {timeout}s" if timeout else "Timeout: None")
        
        # Check permissions
        if platform.system() != "Windows" and os.geteuid() != 0:
            print("⚠️  WARNING: Running without root privileges")
            print("   Packet capture may fail on some systems")
        
        print("-" * 80)
        
        self.running = True
        self.start_time = time.time()
        self.packet_count = 0
        
        # Start session tracking
        self.start_session()
        
        try:
            print("🎯 Starting packet capture... (Press Ctrl+C to stop)")
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                count=packet_count,
                timeout=timeout,
                store=0  # Don't store packets in memory
            )
        except KeyboardInterrupt:
            print("\n⏹️  Capture interrupted by user")
        except Exception as e:
            print(f"\n❌ Capture error: {e}")
            logging.error(f"Capture error: {e}")
        finally:
            self.stop_sniffing()
    
    def stop_sniffing(self):
        """Stop packet capture and show summary"""
        self.running = False
        
        if self.start_time:
            duration = time.time() - self.start_time
            rate = self.packet_count / duration if duration > 0 else 0
            
            print("\n" + "=" * 80)
            print("📊 CAPTURE SUMMARY")
            print("=" * 80)
            print(f"📦 Packets captured: {self.packet_count:,}")
            print(f"⏱️  Duration: {duration:.2f} seconds")
            print(f"🚀 Average rate: {rate:.2f} packets/second")
            
            # Show traffic summary
            summary = self.db_manager.get_traffic_summary(minutes=int(duration/60) + 1)
            if summary:
                print(f"\n🌐 TRAFFIC BREAKDOWN:")
                print("Protocol   | Packets | Bytes     | Unique IPs")
                print("-" * 50)
                for protocol, packets, bytes_total, unique_ips in summary:
                    bytes_str = f"{bytes_total:,}" if bytes_total else "0"
                    print(f"{protocol:10} | {packets:7,} | {bytes_str:9} | {unique_ips:10}")
            
            # End session
            self.end_session()
            
            # Cleanup old data periodically
            if self.packet_count > 0:
                deleted = self.db_manager.cleanup_old_data(30)
                if deleted > 0:
                    print(f"\n🧹 Cleaned up {deleted:,} old packet records")
        
        print("=" * 80)

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Network Packet Sniffer with Anomaly Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python packet_sniffer.py                    # Capture on default interface
  python packet_sniffer.py -i eth0           # Capture on specific interface  
  python packet_sniffer.py -c 1000           # Capture 1000 packets
  python packet_sniffer.py -t 3600           # Capture for 1 hour
  python packet_sniffer.py --list-interfaces # Show available interfaces
        """
    )
    
    parser.add_argument("-i", "--interface", help="Network interface to sniff")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for unlimited)")
    parser.add_argument("-t", "--timeout", type=int, help="Capture timeout in seconds")
    parser.add_argument("--config", default="config.json", help="Configuration file path")
    parser.add_argument("--list-interfaces", action="store_true", help="List available network interfaces")
    parser.add_argument("--init-db", action="store_true", help="Initialize database and exit")
    
    args = parser.parse_args()
    
    # List interfaces
    if args.list_interfaces:
        try:
            interfaces = get_if_list()
            print("Available network interfaces:")
            for i, iface in enumerate(interfaces, 1):
                print(f"  {i}. {iface}")
        except Exception as e:
            print(f"Error listing interfaces: {e}")
        return
    
    # Initialize database
    if args.init_db:
        from db_init import init_database
        init_database()
        return
    
    # Check if database exists
    if not os.path.exists("network_monitor.db"):
        print("❌ Database not found!")
        print("Initialize with: python db_init.py")
        print("Or run: python packet_sniffer.py --init-db")
        return
    
    # Check permissions
    if platform.system() != "Windows" and os.geteuid() != 0:
        print("⚠️  WARNING: This script typically requires root privileges for packet capture")
        print("Try running with: sudo python3 packet_sniffer.py")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            return
    
    # Create and start sniffer
    try:
        sniffer = PacketSniffer(interface=args.interface, config_file=args.config)
        sniffer.start_sniffing(packet_count=args.count, timeout=args.timeout)
    except KeyboardInterrupt:
        print("\n🛑 Shutdown requested by user")
    except Exception as e:
        print(f"❌ Error: {e}")
        logging.error(f"Main error: {e}")

if __name__ == "__main__":
    main()
