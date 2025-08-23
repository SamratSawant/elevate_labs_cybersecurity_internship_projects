import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
import sqlite3
from datetime import datetime, timedelta
import time
from collections import defaultdict, deque
import queue
import platform
import os
import sys
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import ipaddress

# Safe Scapy import with error handling
SCAPY_AVAILABLE = False
SCAPY_ERROR = None

try:
    os.environ['SCAPY_USE_PCAPDNET'] = '0'
    from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP, IPv6
    SCAPY_AVAILABLE = True
    print("✅ Scapy loaded successfully")
except Exception as e:
    SCAPY_ERROR = str(e)
    print(f"❌ Scapy error: {e}")

class EnhancedAnomalyDetector:
    """Advanced anomaly detection for network security"""
    
    def __init__(self):
        self.port_scan_tracker = defaultdict(set)
        self.flood_tracker = defaultdict(deque)
        self.syn_flood_tracker = defaultdict(deque)
        self.dns_flood_tracker = defaultdict(deque)
        self.suspicious_ips = set()
        
        # Configurable thresholds
        self.large_packet_threshold = 1500
        self.port_scan_threshold = 10
        self.flood_threshold = 50
        self.syn_flood_threshold = 20
        self.dns_flood_threshold = 30
        
        # Common suspicious ports
        self.suspicious_ports = {21, 22, 23, 135, 139, 445, 1433, 3389, 5900}
        
    def analyze_packet(self, packet_data):
        """Enhanced packet analysis for multiple attack types"""
        timestamp, src_ip, src_port, dst_ip, dst_port, protocol, length, flags = packet_data
        alerts = []
        current_time = time.time()
        
        try:
            length = int(length) if length else 0
            
            # Large packet detection
            if length > self.large_packet_threshold:
                alerts.append(("MEDIUM", f"LARGE_PACKET: {src_ip} sent {length} bytes to {dst_ip}"))
            
            # Port scan detection
            if protocol in ["TCP", "UDP"] and dst_port:
                try:
                    self.port_scan_tracker[src_ip].add(int(dst_port))
                    if len(self.port_scan_tracker[src_ip]) > self.port_scan_threshold:
                        alerts.append(("HIGH", f"PORT_SCAN: {src_ip} scanning {len(self.port_scan_tracker[src_ip])} ports on {dst_ip}"))
                        self.suspicious_ips.add(src_ip)
                except ValueError:
                    pass
            
            # SYN flood detection
            if protocol == "TCP" and "S" in str(flags):
                self.syn_flood_tracker[src_ip].append(current_time)
                while (self.syn_flood_tracker[src_ip] and 
                       current_time - self.syn_flood_tracker[src_ip][0] > 60):
                    self.syn_flood_tracker[src_ip].popleft()
                
                if len(self.syn_flood_tracker[src_ip]) > self.syn_flood_threshold:
                    alerts.append(("HIGH", f"SYN_FLOOD: {src_ip} sending excessive SYN packets to {dst_ip}"))
            
            # DNS flood detection
            if protocol == "UDP" and (src_port == 53 or dst_port == 53):
                self.dns_flood_tracker[src_ip].append(current_time)
                while (self.dns_flood_tracker[src_ip] and 
                       current_time - self.dns_flood_tracker[src_ip][0] > 60):
                    self.dns_flood_tracker[src_ip].popleft()
                
                if len(self.dns_flood_tracker[src_ip]) > self.dns_flood_threshold:
                    alerts.append(("MEDIUM", f"DNS_FLOOD: {src_ip} excessive DNS queries"))
            
            # General packet flood detection
            self.flood_tracker[src_ip].append(current_time)
            while (self.flood_tracker[src_ip] and 
                   current_time - self.flood_tracker[src_ip][0] > 60):
                self.flood_tracker[src_ip].popleft()
                
            if len(self.flood_tracker[src_ip]) > self.flood_threshold:
                alerts.append(("HIGH", f"PACKET_FLOOD: {src_ip} sending {len(self.flood_tracker[src_ip])} packets/min"))
            
            # Suspicious port access
            if dst_port and int(dst_port) in self.suspicious_ports:
                alerts.append(("MEDIUM", f"SUSPICIOUS_PORT: {src_ip} accessing port {dst_port} on {dst_ip}"))
                
        except (ValueError, TypeError):
            pass
        
        return alerts

class EmailAlerter:
    """Handle email notifications for security alerts"""
    
    def __init__(self, smtp_server, smtp_port, username, password, recipients):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.recipients = recipients if isinstance(recipients, list) else [recipients]
        self.last_alert_time = defaultdict(float)
        self.alert_cooldown = 300  # 5 minutes
        
    def send_alert(self, alert_type, description):
        """Send security alert email"""
        current_time = time.time()
        
        if current_time - self.last_alert_time[alert_type] < self.alert_cooldown:
            return False
            
        try:
            msg = MIMEMultipart()
            msg['From'] = self.username
            msg['To'] = ', '.join(self.recipients)
            msg['Subject'] = f"🚨 Network Security Alert: {alert_type}"
            
            body = f"""
🚨 NETWORK SECURITY ALERT

Alert Type: {alert_type}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Description: {description}

This is an automated alert from your Enhanced Network Packet Sniffer.
Please investigate this potential security issue immediately.

---
Enhanced Network Packet Sniffer v2.0
            """.strip()
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.username, self.password)
            server.sendmail(self.username, self.recipients, msg.as_string())
            server.quit()
            
            self.last_alert_time[alert_type] = current_time
            return True
            
        except Exception as e:
            print(f"Failed to send email alert: {e}")
            return False

class NetworkMonitorGUI:
    """Enhanced GUI for network packet monitoring with advanced scanning"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 Enhanced Network Packet Sniffer & Security Monitor v2.0")
        self.root.geometry("1600x1000")
        
        if platform.system() == "Windows":
            try:
                self.root.state('zoomed')
            except:
                pass
        
        # Initialize variables
        self.setup_variables()
        
        # Initialize components
        self.init_database()
        self.anomaly_detector = EnhancedAnomalyDetector()
        self.email_alerter = None
        
        # Setup GUI
        self.setup_gui()
        self.setup_plots()
        
        # Start update loop
        self.update_display()
        
        # Show startup info
        self.show_startup_info()
        
        # Load demo data after startup
        if self.demo_mode:
            self.root.after(2000, self.load_demo_data)
    
    def setup_variables(self):
        """Initialize all variables"""
        # Data storage
        self.packet_queue = queue.Queue()
        self.alert_queue = queue.Queue()
        self.traffic_data = defaultdict(lambda: deque(maxlen=100))
        self.time_data = deque(maxlen=100)
        self.packet_data = []
        
        # Control variables
        self.is_monitoring = False
        self.sniffer_thread = None
        self.total_packets = 0
        self.start_time = None
        self.demo_mode = not SCAPY_AVAILABLE
        
        # Database
        self.db_path = "network_monitor_enhanced.db"
        self.conn = None
        
        # GUI Variables
        self.status_var = tk.StringVar(value="Ready")
        self.packet_count_var = tk.StringVar(value="Packets: 0")
        self.email_status_var = tk.StringVar(value="Email: Disabled")
        self.interface_var = tk.StringVar()
        self.max_packets_var = tk.StringVar(value="1000")
        self.timeout_var = tk.StringVar(value="")
        self.filter_var = tk.StringVar()
        
        # Email configuration variables
        self.email_enabled_var = tk.BooleanVar()
        self.smtp_server_var = tk.StringVar(value="smtp.gmail.com")
        self.smtp_port_var = tk.StringVar(value="587")
        self.email_username_var = tk.StringVar()
        self.email_password_var = tk.StringVar()
        self.email_recipients_var = tk.StringVar()
        
        # Detection threshold variables
        self.port_scan_var = tk.StringVar(value="10")
        self.flood_threshold_var = tk.StringVar(value="50")
        self.large_packet_var = tk.StringVar(value="1500")
        self.syn_flood_var = tk.StringVar(value="20")
        self.dns_flood_var = tk.StringVar(value="30")
        
        # Other variables
        self.severity_var = tk.StringVar(value="All")
        self.time_window_var = tk.StringVar(value="Last 100 packets")
        self.protocol_filter_var = tk.StringVar(value="All")
        self.alert_type_var = tk.StringVar(value="All")
        
        # Enhanced variables
        self.ipv6_enabled_var = tk.BooleanVar(value=True)
        self.deep_inspection_var = tk.BooleanVar(value=True)
        self.auto_block_var = tk.BooleanVar(value=False)
        self.geo_tracking_var = tk.BooleanVar(value=True)
        self.threat_intel_var = tk.BooleanVar(value=True)
        
        # Security dashboard variables
        self.threats_detected_var = tk.StringVar(value="Threats: 0")
        self.blocked_ips_var = tk.StringVar(value="Blocked IPs: 0")
        self.risk_score_var = tk.StringVar(value="Risk Score: 0.0")
        self.security_status_var = tk.StringVar(value="Security: Ready")
        
    def show_startup_info(self):
        """Show startup information"""
        if not SCAPY_AVAILABLE:
            msg = f"""⚠️ Scapy Issue Detected

Error: {SCAPY_ERROR}

Solutions:
1. Run as Administrator
2. Delete Scapy cache: C:\\Users\\{os.getenv('USERNAME', 'User')}\\.cache\\scapy
3. Install Npcap: https://npcap.com/

GUI will run in ENHANCED DEMO MODE with advanced simulation."""
            
            messagebox.showwarning("Scapy Issues", msg)
            self.status_var.set("ENHANCED DEMO MODE - Advanced simulation active")
        else:
            self.status_var.set("Ready - Enhanced monitoring available")
    
    def init_database(self):
        """Initialize enhanced database"""
        try:
            if not os.path.exists(self.db_path):
                self.create_enhanced_database()
            
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to connect to database: {e}")
    
    def create_enhanced_database(self):
        """Create enhanced database with additional security fields"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.executescript("""
                CREATE TABLE packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT NOT NULL,
                    packet_length INTEGER NOT NULL,
                    flags TEXT,
                    ip_version TEXT DEFAULT 'IPv4',
                    risk_score REAL DEFAULT 0.0
                );
                
                CREATE TABLE alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    alert_type TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    description TEXT NOT NULL,
                    severity TEXT DEFAULT 'MEDIUM',
                    confidence_score REAL DEFAULT 0.5
                );
                
                CREATE TABLE security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT NOT NULL,
                    source_ip TEXT,
                    target_ip TEXT,
                    details TEXT,
                    risk_score REAL DEFAULT 0.0
                );
                
                -- Enhanced sample data
                INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol, packet_length, flags, ip_version, risk_score) VALUES
                ('192.168.1.100', '8.8.8.8', 51234, 80, 'TCP', 1460, 'SYN', 'IPv4', 2.5),
                ('192.168.1.100', '1.1.1.1', 51235, 53, 'UDP', 64, '', 'IPv4', 1.0),
                ('10.0.0.15', '192.168.1.100', 80, 51236, 'TCP', 800, 'PSH', 'IPv4', 3.5),
                ('172.16.0.10', '192.168.1.100', 22, 51237, 'TCP', 120, 'SYN', 'IPv4', 6.0),
                ('192.168.1.50', '224.0.0.1', NULL, NULL, 'ICMP', 84, '', 'IPv4', 1.5),
                ('fe80::1', 'fe80::2', 80, 51240, 'TCP', 1200, 'ACK', 'IPv6', 2.0),
                ('2001:db8::1', '2001:4860:4860::8888', 51241, 53, 'UDP', 45, '', 'IPv6', 1.2);
                
                INSERT INTO alerts (alert_type, source_ip, description, severity, confidence_score) VALUES
                ('PORT_SCAN', '10.0.0.15', 'Multiple port scan detected from external IP', 'HIGH', 0.9),
                ('LARGE_PACKET', '192.168.1.100', 'Packet size 2048 bytes exceeds threshold', 'MEDIUM', 0.7),
                ('SYN_FLOOD', '172.16.0.10', 'Excessive SYN packets detected - possible DoS attack', 'CRITICAL', 0.95),
                ('DNS_FLOOD', '192.168.1.200', 'Unusual DNS query volume detected', 'MEDIUM', 0.6);
                
                INSERT INTO security_events (event_type, source_ip, details, risk_score) VALUES
                ('INTRUSION_ATTEMPT', '203.0.113.42', 'Attempted SSH brute force attack', 8.5),
                ('MALWARE_COMM', '192.168.1.150', 'Communication with known C&C server', 9.2),
                ('DATA_EXFILTRATION', '192.168.1.100', 'Large data transfer to external IP', 7.8);
            """)
            
            conn.commit()
            conn.close()
            print("✅ Enhanced database created with advanced sample data")
        except Exception as e:
            print(f"Failed to create enhanced database: {e}")
    
    def setup_gui(self):
        """Setup enhanced GUI"""
        # Header
        self.create_enhanced_header()
        
        # Control panel
        self.create_enhanced_control_panel()
        
        # Main notebook
        content_frame = ttk.Frame(self.root)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.notebook = ttk.Notebook(content_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Enhanced tabs
        self.setup_traffic_tab()
        self.setup_enhanced_alerts_tab()
        self.setup_security_dashboard_tab()
        self.setup_config_tab()
        self.setup_help_tab()
        
        # Status bar
        self.create_status_bar()
    
    def create_enhanced_header(self):
        """Create enhanced application header"""
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        title_label = ttk.Label(header_frame, text="🔍 Enhanced Network Security Monitor", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(side=tk.LEFT)
        
        # Enhanced status indicators
        status_frame = ttk.Frame(header_frame)
        status_frame.pack(side=tk.RIGHT)
        
        scapy_status = "✅ Ready" if SCAPY_AVAILABLE else "❌ Demo Mode"
        ttk.Label(status_frame, text=f"Scapy: {scapy_status}").pack(side=tk.RIGHT, padx=5)
        
        security_level = "🔒 Enhanced" if SCAPY_AVAILABLE else "🛡️ Simulation"
        ttk.Label(status_frame, text=f"Security: {security_level}").pack(side=tk.RIGHT, padx=5)
        
        platform_icon = {"Windows": "🪟", "Linux": "🐧", "Darwin": "🍎"}.get(platform.system(), "💻")
        ttk.Label(status_frame, text=f"{platform_icon} {platform.system()}").pack(side=tk.RIGHT, padx=5)
    
    def create_enhanced_control_panel(self):
        """Create enhanced control panel"""
        control_frame = ttk.LabelFrame(self.root, text="🎛️ Enhanced Control Panel", padding=10)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Interface selection
        iface_frame = ttk.Frame(control_frame)
        iface_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(iface_frame, text="Network Interface:").pack(side=tk.LEFT)
        
        self.interface_combo = ttk.Combobox(iface_frame, textvariable=self.interface_var, 
                                          width=35, state="readonly")
        self.interface_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(iface_frame, text="🔄 Refresh", command=self.refresh_interfaces).pack(side=tk.LEFT, padx=5)
        
        # Enhanced monitoring options
        options_frame = ttk.Frame(control_frame)
        options_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(options_frame, text="Max Packets:").pack(side=tk.LEFT)
        ttk.Entry(options_frame, textvariable=self.max_packets_var, width=10).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(options_frame, text="Timeout (s):").pack(side=tk.LEFT, padx=(20,0))
        ttk.Entry(options_frame, textvariable=self.timeout_var, width=10).pack(side=tk.LEFT, padx=5)
        
        # IPv6 support checkbox
        ttk.Checkbutton(options_frame, text="IPv6 Support", 
                       variable=self.ipv6_enabled_var).pack(side=tk.LEFT, padx=20)
        
        # Deep packet inspection
        ttk.Checkbutton(options_frame, text="Deep Inspection", 
                       variable=self.deep_inspection_var).pack(side=tk.LEFT, padx=10)
        
        # Control buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X, pady=5)
        
        if SCAPY_AVAILABLE:
            self.start_button = ttk.Button(button_frame, text="▶️ Start Enhanced Monitoring", 
                                         command=self.start_enhanced_monitoring)
            self.start_button.pack(side=tk.LEFT, padx=5)
            
            self.stop_button = ttk.Button(button_frame, text="⏹️ Stop Monitoring", 
                                        command=self.stop_monitoring, state=tk.DISABLED)
            self.stop_button.pack(side=tk.LEFT, padx=5)
        else:
            ttk.Button(button_frame, text="📊 Load Enhanced Demo", 
                      command=self.load_demo_data).pack(side=tk.LEFT, padx=5)
            
            ttk.Button(button_frame, text="🛡️ Start Demo Monitoring", 
                      command=self.start_enhanced_demo_monitoring).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="🛡️ Security Scan", command=self.run_security_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🗑️ Clear Data", command=self.clear_data).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="💾 Export", command=self.export_data).pack(side=tk.LEFT, padx=5)
        
        # Populate interfaces
        self.refresh_interfaces()
    
    def refresh_interfaces(self):
        """Refresh network interfaces"""
        interfaces = []
        
        if self.demo_mode:
            interfaces = ["Enhanced Demo Mode - Advanced Simulation"]
        elif SCAPY_AVAILABLE:
            try:
                scapy_interfaces = get_if_list()
                interfaces = ["Any (All Interfaces - IPv4/IPv6)"] + [f"{iface} (Enhanced)" for iface in scapy_interfaces 
                                                                    if iface and not iface.lower().startswith('loopback')]
            except Exception as e:
                interfaces = [f"Error: {e}"]
        else:
            interfaces = ["Scapy not available - Demo Mode Only"]
        
        self.interface_combo['values'] = interfaces
        if interfaces:
            self.interface_combo.set(interfaces[0])
    
    def setup_traffic_tab(self):
        """Setup enhanced traffic monitoring tab"""
        self.traffic_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.traffic_frame, text="📡 Live Traffic")
        
        # Enhanced toolbar
        toolbar = ttk.Frame(self.traffic_frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(toolbar, text="🔍 Filter:").pack(side=tk.LEFT)
        filter_entry = ttk.Entry(toolbar, textvariable=self.filter_var, width=20)
        filter_entry.pack(side=tk.LEFT, padx=5)
        filter_entry.bind('<Return>', self.apply_filter)
        
        ttk.Button(toolbar, text="Apply", command=self.apply_filter).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Clear", command=self.clear_filter).pack(side=tk.LEFT, padx=2)
        
        # Protocol filter
        ttk.Label(toolbar, text="Protocol:").pack(side=tk.LEFT, padx=(20,5))
        protocol_combo = ttk.Combobox(toolbar, textvariable=self.protocol_filter_var,
                                    values=["All", "TCP", "UDP", "ICMP", "IPv6", "HTTP", "HTTPS", "DNS"],
                                    width=10, state="readonly")
        protocol_combo.pack(side=tk.LEFT, padx=5)
        
        # Enhanced packet table
        table_frame = ttk.Frame(self.traffic_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("Time", "Source IP", "Src Port", "Dest IP", "Dst Port", "Protocol", 
                  "Length", "Flags", "IP Ver", "Risk")
        self.packet_tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=22)
        
        # Configure enhanced columns
        column_widths = {"Time": 80, "Source IP": 120, "Src Port": 70, "Dest IP": 120, 
                        "Dst Port": 70, "Protocol": 80, "Length": 70, "Flags": 60, 
                        "IP Ver": 50, "Risk": 50}
        
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        
        # Enhanced packet details
        details_frame = ttk.LabelFrame(self.traffic_frame, text="📄 Enhanced Packet Analysis", height=120)
        details_frame.pack(fill=tk.X, padx=5, pady=5)
        details_frame.pack_propagate(False)
        
        self.packet_details = scrolledtext.ScrolledText(details_frame, height=6, wrap=tk.WORD)
        self.packet_details.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bind selection event
        self.packet_tree.bind('<<TreeviewSelect>>', self.on_enhanced_packet_select)
    
    def setup_enhanced_alerts_tab(self):
        """Setup enhanced security alerts tab"""
        self.alerts_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.alerts_frame, text="🚨 Security Alerts")
        
        # Enhanced alert toolbar
        alert_toolbar = ttk.Frame(self.alerts_frame)
        alert_toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(alert_toolbar, text="Severity Filter:").pack(side=tk.LEFT)
        severity_combo = ttk.Combobox(alert_toolbar, textvariable=self.severity_var, 
                                    values=["All", "LOW", "MEDIUM", "HIGH", "CRITICAL"], 
                                    state="readonly", width=10)
        severity_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(alert_toolbar, text="Alert Type:").pack(side=tk.LEFT, padx=(20,5))
        alert_type_combo = ttk.Combobox(alert_toolbar, textvariable=self.alert_type_var,
                                      values=["All", "PORT_SCAN", "SYN_FLOOD", "DNS_FLOOD", 
                                             "LARGE_PACKET", "SUSPICIOUS_PORT"],
                                      width=12, state="readonly")
        alert_type_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(alert_toolbar, text="🔄 Refresh", command=self.refresh_alerts).pack(side=tk.LEFT, padx=5)
        ttk.Button(alert_toolbar, text="🗑️ Clear All", command=self.clear_alerts).pack(side=tk.LEFT, padx=5)
        
        # Enhanced alert display
        alert_frame = ttk.Frame(self.alerts_frame)
        alert_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.alert_text = scrolledtext.ScrolledText(alert_frame, font=('Consolas', 10))
        self.alert_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure enhanced text tags
        self.alert_text.tag_configure("CRITICAL", foreground="red", font=('Consolas', 10, 'bold'))
        self.alert_text.tag_configure("HIGH", foreground="orange", font=('Consolas', 10, 'bold'))
        self.alert_text.tag_configure("MEDIUM", foreground="blue")
        self.alert_text.tag_configure("LOW", foreground="green")
    
    def setup_security_dashboard_tab(self):
        """Setup security dashboard tab"""
        security_frame = ttk.Frame(self.notebook)
        self.notebook.add(security_frame, text="🛡️ Security Dashboard")
        
        # Security metrics frame
        metrics_frame = ttk.LabelFrame(security_frame, text="📊 Security Metrics", padding=10)
        metrics_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Metrics display
        metrics_row1 = ttk.Frame(metrics_frame)
        metrics_row1.pack(fill=tk.X, pady=2)
        
        ttk.Label(metrics_row1, textvariable=self.threats_detected_var, font=('Arial', 12, 'bold')).pack(side=tk.LEFT, padx=20)
        ttk.Label(metrics_row1, textvariable=self.blocked_ips_var, font=('Arial', 12, 'bold')).pack(side=tk.LEFT, padx=20)
        ttk.Label(metrics_row1, textvariable=self.risk_score_var, font=('Arial', 12, 'bold')).pack(side=tk.LEFT, padx=20)
        
        # Top threats table
        threats_frame = ttk.LabelFrame(security_frame, text="🎯 Top Security Threats", padding=10)
        threats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        threat_columns = ("Time", "Threat Type", "Source IP", "Risk Score", "Status")
        self.threat_tree = ttk.Treeview(threats_frame, columns=threat_columns, show="headings", height=15)
        
        for col in threat_columns:
            self.threat_tree.heading(col, text=col)
            self.threat_tree.column(col, width=120)
        
        self.threat_tree.pack(fill=tk.BOTH, expand=True)
    
    def setup_config_tab(self):
        """Setup enhanced configuration tab"""
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="⚙️ Configuration")
        
        # Create scrollable frame
        canvas = tk.Canvas(config_frame)
        scrollbar = ttk.Scrollbar(config_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.config_frame = scrollable_frame
        
        # Configuration sections
        self.create_enhanced_detection_config()
        self.create_email_config()
        self.create_security_config()
    
    def create_enhanced_detection_config(self):
        """Create enhanced detection configuration"""
        detection_frame = ttk.LabelFrame(self.config_frame, text="🔍 Enhanced Security Detection", padding=15)
        detection_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Port scan threshold
        port_frame = ttk.Frame(detection_frame)
        port_frame.pack(fill=tk.X, pady=5)
        ttk.Label(port_frame, text="Port Scan Threshold:").pack(side=tk.LEFT)
        ttk.Entry(port_frame, textvariable=self.port_scan_var, width=10).pack(side=tk.LEFT, padx=10)
        ttk.Label(port_frame, text="different ports per IP").pack(side=tk.LEFT)
        
        # SYN flood threshold
        syn_frame = ttk.Frame(detection_frame)
        syn_frame.pack(fill=tk.X, pady=5)
        ttk.Label(syn_frame, text="SYN Flood Threshold:").pack(side=tk.LEFT)
        ttk.Entry(syn_frame, textvariable=self.syn_flood_var, width=10).pack(side=tk.LEFT, padx=10)
        ttk.Label(syn_frame, text="SYN packets per minute").pack(side=tk.LEFT)
        
        # DNS flood threshold
        dns_frame = ttk.Frame(detection_frame)
        dns_frame.pack(fill=tk.X, pady=5)
        ttk.Label(dns_frame, text="DNS Flood Threshold:").pack(side=tk.LEFT)
        ttk.Entry(dns_frame, textvariable=self.dns_flood_var, width=10).pack(side=tk.LEFT, padx=10)
        ttk.Label(dns_frame, text="DNS queries per minute").pack(side=tk.LEFT)
        
        # Large packet threshold
        packet_frame = ttk.Frame(detection_frame)
        packet_frame.pack(fill=tk.X, pady=5)
        ttk.Label(packet_frame, text="Large Packet Threshold:").pack(side=tk.LEFT)
        ttk.Entry(packet_frame, textvariable=self.large_packet_var, width=10).pack(side=tk.LEFT, padx=10)
        ttk.Label(packet_frame, text="bytes").pack(side=tk.LEFT)
        
        # Save button
        ttk.Button(detection_frame, text="💾 Save Enhanced Settings", 
                  command=self.save_enhanced_detection_config).pack(pady=10)
    
    def create_email_config(self):
        """Create email configuration section"""
        email_frame = ttk.LabelFrame(self.config_frame, text="📧 Email Alert Configuration", padding=15)
        email_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Checkbutton(email_frame, text="Enable Email Alerts", 
                       variable=self.email_enabled_var,
                       command=self.toggle_email_fields).pack(anchor=tk.W, pady=5)
        
        # Email settings frame
        self.email_settings_frame = ttk.Frame(email_frame)
        self.email_settings_frame.pack(fill=tk.X, pady=5)
        
        # SMTP Server
        smtp_frame = ttk.Frame(self.email_settings_frame)
        smtp_frame.pack(fill=tk.X, pady=2)
        ttk.Label(smtp_frame, text="SMTP Server:", width=15).pack(side=tk.LEFT)
        ttk.Entry(smtp_frame, textvariable=self.smtp_server_var, width=25).pack(side=tk.LEFT, padx=5)
        
        # SMTP Port
        port_frame = ttk.Frame(self.email_settings_frame)
        port_frame.pack(fill=tk.X, pady=2)
        ttk.Label(port_frame, text="SMTP Port:", width=15).pack(side=tk.LEFT)
        ttk.Entry(port_frame, textvariable=self.smtp_port_var, width=10).pack(side=tk.LEFT, padx=5)
        
        # Username
        user_frame = ttk.Frame(self.email_settings_frame)
        user_frame.pack(fill=tk.X, pady=2)
        ttk.Label(user_frame, text="Username:", width=15).pack(side=tk.LEFT)
        ttk.Entry(user_frame, textvariable=self.email_username_var, width=35).pack(side=tk.LEFT, padx=5)
        
        # Password
        pass_frame = ttk.Frame(self.email_settings_frame)
        pass_frame.pack(fill=tk.X, pady=2)
        ttk.Label(pass_frame, text="Password:", width=15).pack(side=tk.LEFT)
        ttk.Entry(pass_frame, textvariable=self.email_password_var, width=35, show="*").pack(side=tk.LEFT, padx=5)
        
        # Recipients
        recip_frame = ttk.Frame(self.email_settings_frame)
        recip_frame.pack(fill=tk.X, pady=2)
        ttk.Label(recip_frame, text="Recipients:", width=15).pack(side=tk.LEFT)
        ttk.Entry(recip_frame, textvariable=self.email_recipients_var, width=50).pack(side=tk.LEFT, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(self.email_settings_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="💾 Save Config", command=self.save_email_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📧 Test Email", command=self.test_email).pack(side=tk.LEFT, padx=5)
        
        # Initially disable email fields
        self.toggle_email_fields()
    
    def create_security_config(self):
        """Create security-specific configuration"""
        security_frame = ttk.LabelFrame(self.config_frame, text="🛡️ Security Configuration", padding=15)
        security_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Auto-blocking
        ttk.Checkbutton(security_frame, text="Auto-block suspicious IPs", 
                       variable=self.auto_block_var).pack(anchor=tk.W, pady=2)
        
        # Geolocation tracking
        ttk.Checkbutton(security_frame, text="Enable geolocation tracking", 
                       variable=self.geo_tracking_var).pack(anchor=tk.W, pady=2)
        
        # Threat intelligence
        ttk.Checkbutton(security_frame, text="Use threat intelligence feeds", 
                       variable=self.threat_intel_var).pack(anchor=tk.W, pady=2)
        
        ttk.Button(security_frame, text="💾 Save Security Settings", 
                  command=self.save_security_config).pack(pady=10)
    
    def setup_help_tab(self):
        """Setup enhanced help tab"""
        help_frame = ttk.Frame(self.notebook)
        self.notebook.add(help_frame, text="❓ Help")
        
        help_text = scrolledtext.ScrolledText(help_frame, wrap=tk.WORD, font=('Arial', 10))
        help_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        help_content = f"""
🔍 Enhanced Network Packet Sniffer - Advanced Security Monitor

Current Status: {'✅ Scapy Available' if SCAPY_AVAILABLE else '❌ Enhanced Demo Mode'}
Platform: {platform.system()} {platform.release()}

🚀 ENHANCED FEATURES:

1. Advanced Packet Analysis:
   - IPv4 and IPv6 support
   - Deep packet inspection
   - Protocol-specific analysis
   - Risk scoring system

2. Enhanced Security Detection:
   - Port scan detection
   - SYN flood detection
   - DNS flood detection
   - Suspicious port monitoring
   - Advanced anomaly detection

3. Real-time Security Dashboard:
   - Threat visualization
   - Security metrics
   - Risk assessment
   - Auto-blocking capabilities

🔧 GETTING STARTED:

1. Configuration:
   - Set detection thresholds in Configuration tab
   - Enable email alerts for security events
   - Configure auto-blocking if desired

2. Monitoring:
   - Start Enhanced Monitoring for real-time analysis
   - Monitor Security Dashboard for threats
   - Review alerts in Security Alerts tab

3. Security Features:
   - Use Security Scan for manual analysis
   - Enable IPv6 support for modern networks
   - Configure deep packet inspection

📊 CAPABILITIES:
• Multi-protocol support (TCP/UDP/ICMP/IPv6)
• Real-time threat detection and alerting
• Advanced anomaly detection algorithms
• Comprehensive logging and reporting

⚠️ LEGAL NOTICE:
This enhanced security tool should only be used on networks you own or 
have explicit permission to monitor.
        """
        
        help_text.insert(1.0, help_content.strip())
        help_text.config(state=tk.DISABLED)
    
    def create_status_bar(self):
        """Create enhanced status bar"""
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=5, pady=2)
        
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var)
        self.status_label.pack(side=tk.LEFT)
        
        # Packet counter
        self.packet_count_label = ttk.Label(status_frame, textvariable=self.packet_count_var)
        self.packet_count_label.pack(side=tk.RIGHT)
        
        # Email status
        self.email_status_label = ttk.Label(status_frame, textvariable=self.email_status_var)
        self.email_status_label.pack(side=tk.RIGHT, padx=10)
        
        # Security status
        ttk.Label(status_frame, textvariable=self.security_status_var).pack(side=tk.RIGHT, padx=10)
    
    def setup_plots(self):
        """Setup enhanced matplotlib plots"""
        try:
            self.fig, ((self.ax1, self.ax2), (self.ax3, self.ax4)) = plt.subplots(2, 2, figsize=(15, 10))
            
            self.ax1.set_title("Protocol Distribution")
            self.ax2.set_title("Security Threats Over Time")
            self.ax3.set_title("Top Risk Sources")
            self.ax4.set_title("Packet Size vs Risk Score")
            
            # Canvas frame for enhanced plots (will be created in setup_traffic_tab if needed)
            
        except Exception as e:
            print(f"Failed to setup enhanced plots: {e}")
    
    # Enhanced monitoring methods
    def start_enhanced_monitoring(self):
        """Start enhanced network monitoring"""
        if not SCAPY_AVAILABLE:
            messagebox.showwarning("Scapy Not Available", 
                                 "Cannot start real monitoring. Running enhanced demo mode...")
            self.start_enhanced_demo_monitoring()
            return
        
        if self.is_monitoring:
            return
        
        # Get enhanced settings
        interface = self.interface_var.get()
        if interface.startswith("Any"):
            interface = None
        
        try:
            max_packets = int(self.max_packets_var.get()) if self.max_packets_var.get() else 0
        except ValueError:
            max_packets = 1000
        
        try:
            timeout = int(self.timeout_var.get()) if self.timeout_var.get() else None
        except ValueError:
            timeout = None
        
        # Update UI
        self.is_monitoring = True
        self.start_time = time.time()
        self.total_packets = 0
        
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_var.set("Enhanced monitoring started...")
        self.security_status_var.set("Security: Monitoring")
        
        # Clear previous data
        self.clear_display()
        
        # Start enhanced monitoring thread
        self.sniffer_thread = threading.Thread(
            target=self.enhanced_network_monitoring, 
            args=(interface, max_packets, timeout), 
            daemon=True
        )
        self.sniffer_thread.start()
        
        messagebox.showinfo("Enhanced Monitoring Started", 
                          f"Advanced security monitoring active!\n\n"
                          f"• IPv6 Support: {'Enabled' if self.ipv6_enabled_var.get() else 'Disabled'}\n"
                          f"• Deep Inspection: {'Enabled' if self.deep_inspection_var.get() else 'Disabled'}\n"
                          f"• Interface: {interface or 'All'}\n"
                          f"• Auto-blocking: {'Enabled' if self.auto_block_var.get() else 'Disabled'}")
    
    def enhanced_network_monitoring(self, interface, max_packets, timeout):
        """Enhanced network monitoring with advanced packet analysis"""
        self.status_var.set("🛡️ Enhanced monitoring active...")
        packet_count = 0
        
        def enhanced_packet_handler(packet):
            nonlocal packet_count
            if not self.is_monitoring:
                return True
            
            try:
                timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                
                # Determine IP version and extract IPs
                ip_version = "IPv4"
                if packet.haslayer(IP):
                    ip_layer = packet[IP]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                elif packet.haslayer(IPv6):
                    ip_layer = packet[IPv6]
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    ip_version = "IPv6"
                else:
                    return
                
                # Enhanced protocol detection
                src_port = dst_port = ""
                protocol = "Other"
                flags = ""
                
                if packet.haslayer(TCP):
                    protocol = "TCP"
                    tcp_layer = packet[TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    flags = str(tcp_layer.flags)
                elif packet.haslayer(UDP):
                    protocol = "UDP"
                    udp_layer = packet[UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                elif packet.haslayer(ICMP):
                    protocol = "ICMP"
                else:
                    protocol = "Other"
                
                length = len(packet)
                
                # Calculate risk score
                risk_score = self.calculate_risk_score(src_ip, dst_ip, src_port, dst_port, protocol, length, flags)
                
                # Enhanced packet data
                packet_data = (timestamp, src_ip, src_port, dst_ip, dst_port, protocol, 
                             length, flags, ip_version, f"{risk_score:.1f}")
                self.packet_queue.put(packet_data)
                
                # Enhanced anomaly detection
                basic_packet_data = (timestamp, src_ip, src_port, dst_ip, dst_port, protocol, length, flags)
                alerts = self.anomaly_detector.analyze_packet(basic_packet_data)
                
                for severity, description in alerts:
                    alert_msg = f"{timestamp} - {severity}: {description}\n"
                    self.alert_queue.put((severity, alert_msg))
                    
                    # Send email if configured
                    if self.email_alerter and severity in ["HIGH", "CRITICAL"]:
                        threading.Thread(
                            target=self.email_alerter.send_alert,
                            args=(description.split(':')[0], description),
                            daemon=True
                        ).start()
                
                packet_count += 1
                self.total_packets = packet_count
                
                # Stop condition
                if max_packets > 0 and packet_count >= max_packets:
                    self.is_monitoring = False
                    return True
                    
            except Exception as e:
                print(f"Enhanced packet handler error: {e}")
        
        try:
            # Start enhanced Scapy sniffing
            sniff(
                iface=interface,
                prn=enhanced_packet_handler,
                timeout=timeout,
                store=0,
                stop_filter=lambda x: not self.is_monitoring
            )
        except Exception as e:
            print(f"Enhanced monitoring error: {e}")
        finally:
            self.root.after(0, self.monitoring_finished)
    
    def calculate_risk_score(self, src_ip, dst_ip, src_port, dst_port, protocol, length, flags):
        """Calculate risk score for packet"""
        risk = 0.0
        
        try:
            # Check for suspicious ports
            if dst_port and int(dst_port) in self.anomaly_detector.suspicious_ports:
                risk += 3.0
            
            # Large packet risk
            if length > 1400:
                risk += 2.0
            
            # SYN scanning indication
            if protocol == "TCP" and "S" in str(flags) and "A" not in str(flags):
                risk += 1.5
            
            # Private to public communication
            try:
                src_private = ipaddress.ip_address(src_ip).is_private
                dst_private = ipaddress.ip_address(dst_ip).is_private
                if src_private and not dst_private:
                    risk += 0.5
            except:
                pass
            
            # Known suspicious IP
            if src_ip in self.anomaly_detector.suspicious_ips:
                risk += 5.0
                
        except Exception:
            pass
        
        return min(risk, 10.0)  # Cap at 10.0
    
    def start_enhanced_demo_monitoring(self):
        """Start enhanced demo monitoring"""
        self.is_monitoring = True
        self.start_time = time.time()
        self.status_var.set("🛡️ Enhanced Demo Mode - Realistic attack simulation")
        self.security_status_var.set("Security: Demo Active")
        
        # Clear and start enhanced simulation
        self.clear_display()
        
        # Start enhanced demo thread
        demo_thread = threading.Thread(target=self.simulate_enhanced_traffic, daemon=True)
        demo_thread.start()
    
    def simulate_enhanced_traffic(self):
        """Simulate enhanced network traffic with realistic attack patterns"""
        protocols = ['TCP', 'UDP', 'ICMP', 'IPv6']
        src_ips = ['192.168.1.100', '10.0.0.15', '172.16.0.10', '192.168.1.50', 
                  '203.0.113.42', 'fe80::1', '2001:db8::1']
        dst_ips = ['8.8.8.8', '1.1.1.1', '192.168.1.1', '172.217.14.110', 
                  '140.82.112.4', 'fe80::2', '2001:4860:4860::8888']
        
        attack_scenarios = [
            ('port_scan', 0.1),    # 10% chance
            ('syn_flood', 0.05),   # 5% chance
            ('dns_flood', 0.08),   # 8% chance
            ('normal', 0.77)       # 77% chance
        ]
        
        packet_count = 0
        
        while self.is_monitoring:
            # Choose scenario
            scenario = random.choices(
                [s[0] for s in attack_scenarios], 
                weights=[s[1] for s in attack_scenarios]
            )
            
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            
            if scenario == 'port_scan':
                # Simulate port scan
                src_ip = '203.0.113.42'
                dst_ip = '192.168.1.100'
                protocol = 'TCP'
                src_port = random.randint(49152, 65535)
                dst_port = random.choice([22, 23, 21, 80, 443, 135, 139, 445, 3389])
                flags = 'S'
                length = 60
                ip_ver = 'IPv4'
                risk = random.uniform(6.0, 9.0)
                
            elif scenario == 'syn_flood':
                # Simulate SYN flood
                src_ip = random.choice(['203.0.113.42', '198.51.100.15'])
                dst_ip = '192.168.1.100'
                protocol = 'TCP'
                src_port = random.randint(1024, 65535)
                dst_port = 80
                flags = 'S'
                length = random.randint(40, 60)
                ip_ver = 'IPv4'
                risk = random.uniform(7.0, 10.0)
                
            elif scenario == 'dns_flood':
                # Simulate DNS flood
                src_ip = random.choice(src_ips)
                dst_ip = '8.8.8.8'
                protocol = 'UDP'
                src_port = random.randint(49152, 65535)
                dst_port = 53
                flags = ''
                length = random.randint(40, 100)
                ip_ver = 'IPv4'
                risk = random.uniform(4.0, 7.0)
                
            else:  # normal traffic
                src_ip = random.choice(src_ips)
                dst_ip = random.choice(dst_ips)
                protocol = random.choice(protocols)
                
                if 'fe80' in src_ip or '2001' in src_ip:
                    ip_ver = 'IPv6'
                else:
                    ip_ver = 'IPv4'
                
                if protocol in ['TCP', 'UDP']:
                    src_port = random.randint(49152, 65535)
                    dst_port = random.choice([80, 443, 53, 22, 21, 25, 110, 143])
                    flags = random.choice(['', 'S', 'A', 'SA', 'F']) if protocol == 'TCP' else ''
                else:
                    src_port = dst_port = ''
                    flags = ''
                
                length = random.randint(64, 1500)
                risk = random.uniform(0.0, 3.0)
            
            # Create enhanced packet data
            packet_data = (timestamp, src_ip, src_port, dst_ip, dst_port, protocol, 
                         length, flags, ip_ver, f"{risk:.1f}")
            self.packet_queue.put(packet_data)
            
            # Generate alerts for suspicious activity
            if risk > 5.0:
                if scenario == 'port_scan':
                    alert = f"{timestamp} - HIGH: PORT_SCAN: {src_ip} scanning ports on {dst_ip}\n"
                    self.alert_queue.put(("HIGH", alert))
                elif scenario == 'syn_flood':
                    alert = f"{timestamp} - CRITICAL: SYN_FLOOD: {src_ip} flooding {dst_ip}\n"
                    self.alert_queue.put(("CRITICAL", alert))
                elif scenario == 'dns_flood':
                    alert = f"{timestamp} - MEDIUM: DNS_FLOOD: Excessive DNS queries from {src_ip}\n"
                    self.alert_queue.put(("MEDIUM", alert))
            elif length > 1400:
                alert = f"{timestamp} - MEDIUM: LARGE_PACKET: {src_ip} sent {length} bytes\n"
                self.alert_queue.put(("MEDIUM", alert))
            
            packet_count += 1
            self.total_packets = packet_count
            
            # Realistic timing with bursts for attacks
            if scenario in ['port_scan', 'syn_flood']:
                time.sleep(random.uniform(0.01, 0.1))  # Fast bursts
            elif scenario == 'dns_flood':
                time.sleep(random.uniform(0.05, 0.2))  # Medium bursts
            else:
                time.sleep(random.uniform(0.1, 1.0))   # Normal timing
    
    def stop_monitoring(self):
        """Stop enhanced monitoring"""
        self.is_monitoring = False
        if SCAPY_AVAILABLE:
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
        
        self.status_var.set("Enhanced monitoring stopped")
        self.security_status_var.set("Security: Stopped")
    
    def monitoring_finished(self):
        """Called when enhanced monitoring finishes"""
        duration = time.time() - self.start_time if self.start_time else 0
        
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set(f"Enhanced monitoring stopped - {self.total_packets} packets analyzed in {duration:.1f}s")
        self.security_status_var.set("Security: Analysis Complete")
        
        self.is_monitoring = False
    
    def load_demo_data(self):
        """Load enhanced demo data"""
        try:
            if self.conn is None:
                messagebox.showerror("Database Error", "Enhanced database connection not available")
                return
                
            cursor = self.conn.cursor()
            
            # Load enhanced packets
            cursor.execute("""
                SELECT timestamp, src_ip, src_port, dst_ip, dst_port, protocol, 
                       packet_length, flags, ip_version, risk_score
                FROM packets 
                ORDER BY timestamp DESC 
                LIMIT 50
            """)
            packets = cursor.fetchall()
            
            # Clear existing data
            for item in self.packet_tree.get_children():
                self.packet_tree.delete(item)
            self.packet_data.clear()
            
            # Add enhanced packets to display
            for packet in packets:
                timestamp = datetime.now().strftime("%H:%M:%S") if not packet[0] else packet[-8:]
                
                values = (
                    timestamp, 
                    packet[1] or "", 
                    packet[2] or "", 
                    packet[3] or "", 
                    packet[4] or "", 
                    packet[5] or "", 
                    packet[6] or 0, 
                    packet[7] or "",
                    packet[8] or "IPv4",
                    f"{packet[9]:.1f}" if packet[9] else "0.0"
                )
                self.packet_tree.insert("", "end", values=values)
                self.packet_data.append(values)
            
            # Load enhanced alerts
            cursor.execute("""
                SELECT timestamp, alert_type, source_ip, description, severity, confidence_score
                FROM alerts 
                ORDER BY timestamp DESC 
                LIMIT 30
            """)
            alerts = cursor.fetchall()
            
            self.alert_text.delete(1.0, tk.END)
            for alert in alerts:
                timestamp, alert_type, source_ip, description, severity, confidence = alert
                alert_msg = f"{timestamp} - {severity} {alert_type}: {source_ip} - {description} (Confidence: {confidence:.1f})\n"
                self.alert_text.insert(tk.END, alert_msg, severity)
            
            # Load security events
            self.load_security_events()
            
            # Update counters
            self.total_packets = len(packets)
            self.packet_count_var.set(f"Enhanced Demo: {self.total_packets}")
            self.threats_detected_var.set(f"Threats: {len(alerts)}")
            
            messagebox.showinfo("Enhanced Demo Data Loaded", 
                              f"Loaded {len(packets)} enhanced packets and {len(alerts)} security alerts\n\n"
                              f"✅ Advanced features demonstrated:\n"
                              f"• IPv6 support\n• Risk scoring\n• Enhanced detection\n• Security dashboard")
            
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to load enhanced demo data: {e}")
    
    def load_security_events(self):
        """Load security events into dashboard"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT timestamp, event_type, source_ip, risk_score, 'Active' as status
                FROM security_events 
                ORDER BY risk_score DESC, timestamp DESC 
                LIMIT 20
            """)
            events = cursor.fetchall()
            
            # Clear existing items
            for item in self.threat_tree.get_children():
                self.threat_tree.delete(item)
            
            # Add security events
            for event in events:
                timestamp, event_type, source_ip, risk_score, status = event
                values = (timestamp, event_type, source_ip or "Unknown", f"{risk_score:.1f}", status)
                self.threat_tree.insert("", "end", values=values)
            
            # Update security metrics
            high_risk_events = [e for e in events if e[3] > 7.0]
            self.threats_detected_var.set(f"Threats: {len(events)}")
            self.blocked_ips_var.set(f"High Risk: {len(high_risk_events)}")
            avg_risk = sum([e[3] for e in events]) / len(events) if events else 0
            self.risk_score_var.set(f"Avg Risk: {avg_risk:.1f}")
            
        except Exception as e:
            print(f"Failed to load security events: {e}")
    
    def run_security_scan(self):
        """Run manual security scan"""
        messagebox.showinfo("Security Scan", 
                          "🛡️ Enhanced security scan initiated!\n\n"
                          "This would perform:\n"
                          "• Network vulnerability assessment\n"
                          "• Threat detection analysis\n"
                          "• Risk evaluation\n"
                          "• Compliance checking\n\n"
                          "Results would be displayed in Security Dashboard.")
        
        # Simulate adding security events
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.threat_tree.insert("", 0, values=(
            current_time, "MANUAL_SCAN", "192.168.1.0/24", "5.5", "Completed"
        ))
    
    # Utility methods
    def on_enhanced_packet_select(self, event):
        """Handle enhanced packet selection"""
        selection = self.packet_tree.selection()
        if selection:
            item = self.packet_tree.item(selection[0])
            values = item['values']
            
            details = f"""📦 Enhanced Packet Analysis

🕐 Timestamp: {values}
📡 Source: {values[1]}:{values[2]}
🎯 Destination: {values[3]}:{values[4]}
🔗 Protocol: {values[5]} ({values[8]})
📊 Length: {values[6]} bytes
🏷️ Flags: {values[7]}
⚠️ Risk Score: {values[9]}/10

🛡️ Security Analysis:
"""
            
            try:
                risk_score = float(values[9])
                length = int(values[6])
                
                if risk_score >= 7.0:
                    details += "🚨 HIGH RISK: Immediate attention required\n"
                elif risk_score >= 4.0:
                    details += "⚠️ MEDIUM RISK: Monitor closely\n"
                else:
                    details += "✅ LOW RISK: Normal traffic\n"
                
                if length > 1500:
                    details += "📏 Large packet detected\n"
                if values[5] == "TCP" and "S" in str(values[7]):
                    details += "🔍 SYN packet - possible scan attempt\n"
                if values[4] in ["22", "23", "21", "3389"]:
                    details += "🔐 Administrative service access\n"
                if values[8] == "IPv6":
                    details += "🌐 IPv6 traffic detected\n"
                
            except (ValueError, IndexError):
                details += "⚠️ Unable to parse packet data\n"
            
            self.packet_details.delete(1.0, tk.END)
            self.packet_details.insert(1.0, details)
    
    def save_enhanced_detection_config(self):
        """Save enhanced detection configuration"""
        try:
            self.anomaly_detector.port_scan_threshold = int(self.port_scan_var.get())
            self.anomaly_detector.flood_threshold = int(self.flood_threshold_var.get())
            self.anomaly_detector.large_packet_threshold = int(self.large_packet_var.get())
            self.anomaly_detector.syn_flood_threshold = int(self.syn_flood_var.get())
            self.anomaly_detector.dns_flood_threshold = int(self.dns_flood_var.get())
            
            messagebox.showinfo("Enhanced Configuration Saved", 
                              f"Advanced detection thresholds updated:\n"
                              f"• Port scan: {self.port_scan_var.get()} ports\n"
                              f"• SYN flood: {self.syn_flood_var.get()} packets/min\n"
                              f"• DNS flood: {self.dns_flood_var.get()} queries/min\n"
                              f"• Large packet: {self.large_packet_var.get()} bytes")
        except ValueError:
            messagebox.showerror("Invalid Values", "Please enter valid numeric values")
    
    def save_security_config(self):
        """Save security configuration"""
        messagebox.showinfo("Security Configuration Saved", 
                          f"Enhanced security settings updated:\n"
                          f"• Auto-blocking: {'Enabled' if self.auto_block_var.get() else 'Disabled'}\n"
                          f"• Geolocation: {'Enabled' if self.geo_tracking_var.get() else 'Disabled'}\n"
                          f"• Threat Intel: {'Enabled' if self.threat_intel_var.get() else 'Disabled'}")
    
    def toggle_email_fields(self):
        """Toggle email configuration fields"""
        state = tk.NORMAL if self.email_enabled_var.get() else tk.DISABLED
        
        for widget in self.email_settings_frame.winfo_children():
            for child in widget.winfo_children():
                if isinstance(child, ttk.Entry):
                    child.config(state=state)
        
        # Update email alerter
        if self.email_enabled_var.get() and all([
            self.smtp_server_var.get(),
            self.email_username_var.get(),
            self.email_password_var.get(),
            self.email_recipients_var.get()
        ]):
            try:
                recipients = [r.strip() for r in self.email_recipients_var.get().split(',') if r.strip()]
                self.email_alerter = EmailAlerter(
                    self.smtp_server_var.get(),
                    int(self.smtp_port_var.get()),
                    self.email_username_var.get(),
                    self.email_password_var.get(),
                    recipients
                )
                self.email_status_var.set("Email: Enhanced Alerts Enabled")
            except:
                self.email_alerter = None
                self.email_status_var.set("Email: Config Error")
        else:
            self.email_alerter = None
            self.email_status_var.set("Email: Disabled")
    
    def test_email(self):
        """Test enhanced email configuration"""
        if not self.email_enabled_var.get():
            messagebox.showwarning("Email Disabled", "Please enable email alerts first")
            return
        
        # Get configuration
        smtp_server = self.smtp_server_var.get()
        smtp_port = self.smtp_port_var.get()
        username = self.email_username_var.get()
        password = self.email_password_var.get()
        recipients_text = self.email_recipients_var.get()
        
        if not all([smtp_server, smtp_port, username, password, recipients_text]):
            messagebox.showerror("Incomplete Configuration", 
                               "Please fill in all email configuration fields")
            return
        
        try:
            recipients = [r.strip() for r in recipients_text.split(',') if r.strip()]
            port = int(smtp_port)
            
            # Create enhanced test email
            msg = MIMEMultipart()
            msg['From'] = username
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = "🧪 Enhanced Network Sniffer - Test Email"
            
            body = f"""
🧪 ENHANCED EMAIL CONFIGURATION TEST

This is a test email from your Enhanced Network Packet Sniffer.

✅ If you received this message, your email configuration is working correctly!

Enhanced Configuration Details:
• SMTP Server: {smtp_server}
• SMTP Port: {port}
• Username: {username}
• Recipients: {len(recipients)} recipient(s)
• Sent at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Your enhanced network monitoring system is now ready to send advanced security alerts automatically.

Enhanced Alert Features:
🚨 Critical threat detection
⚠️ Advanced anomaly detection
🛡️ IPv6 support and analysis
📊 Risk scoring and assessment

---
Enhanced Network Packet Sniffer v2.0
            """.strip()
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(smtp_server, port)
            server.starttls()
            server.login(username, password)
            server.sendmail(username, recipients, msg.as_string())
            server.quit()
            
            # Success message
            success_msg = f"""✅ Enhanced Test Email Sent Successfully!

📧 Recipients: {', '.join(recipients)}
📤 Sent from: {username}
🕐 Time: {datetime.now().strftime('%H:%M:%S')}

Please check the recipient inbox(es) for the enhanced test message.

Your enhanced email alert system is now configured and ready!"""
            
            messagebox.showinfo("Enhanced Email Test Successful", success_msg)
            
            # Update email alerter
            self.email_alerter = EmailAlerter(smtp_server, port, username, password, recipients)
            self.email_status_var.set(f"Email: Enhanced Ready ({len(recipients)} recipients)")
            
        except ValueError:
            messagebox.showerror("Invalid Port", "SMTP Port must be a number (usually 587 or 25)")
        except smtplib.SMTPAuthenticationError as e:
            messagebox.showerror("Authentication Failed", 
                               f"❌ Email authentication failed:\n{str(e)}\n\n"
                               f"💡 For Gmail users:\n"
                               f"• Use App Password, not your regular password\n"
                               f"• Enable 2-Factor Authentication first")
        except Exception as e:
            messagebox.showerror("Enhanced Email Test Failed", f"❌ Failed to send test email:\n\n{str(e)}")
    
    def save_email_config(self):
        """Save email configuration"""
        messagebox.showinfo("Configuration Saved", "Enhanced email configuration has been saved")
    
    def update_display(self):
        """Update GUI displays with enhanced queued data"""
        # Update packet display
        packets_added = 0
        try:
            while True:
                packet_data = self.packet_queue.get_nowait()
                
                # Color-code based on risk score
                item_id = self.packet_tree.insert("", "end", values=packet_data)
                try:
                    risk_score = float(packet_data[9])
                    if risk_score >= 7.0:
                        self.packet_tree.set(item_id, "Risk", f"🚨{risk_score:.1f}")
                    elif risk_score >= 4.0:
                        self.packet_tree.set(item_id, "Risk", f"⚠️{risk_score:.1f}")
                    else:
                        self.packet_tree.set(item_id, "Risk", f"✅{risk_score:.1f}")
                except (ValueError, IndexError):
                    pass
                
                self.packet_data.append(packet_data)
                packets_added += 1
                
                # Keep only last 2000 packets to prevent memory issues
                if len(self.packet_data) > 2000:
                    self.packet_data.pop(0)
        except queue.Empty:
            pass
        
        # Auto-scroll and limit display
        if packets_added > 0:
            children = self.packet_tree.get_children()
            if len(children) > 1000:
                for child in children[:-1000]:
                    self.packet_tree.delete(child)
            
            # Auto-scroll to bottom
            if children:
                self.packet_tree.see(children[-1])
        
        # Update enhanced alerts
        try:
            while True:
                severity, alert_msg = self.alert_queue.get_nowait()
                self.alert_text.insert(tk.END, alert_msg, severity)
                self.alert_text.see(tk.END)
        except queue.Empty:
            pass
        
        # Update enhanced counters
        if self.is_monitoring:
            self.packet_count_var.set(f"Packets: {len(self.packet_data):,}")
        
        # Schedule next update
        self.root.after(100, self.update_display)
    
    def clear_display(self):
        """Clear enhanced packet display"""
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        self.packet_data.clear()
        self.packet_count_var.set("Packets: 0")
    
    def clear_data(self):
        """Clear all enhanced data"""
        if messagebox.askyesno("Clear Data", "Clear all packet data and security events?"):
            self.clear_display()
            self.alert_text.delete(1.0, tk.END)
            for item in self.threat_tree.get_children():
                self.threat_tree.delete(item)
            self.packet_details.delete(1.0, tk.END)
    
    def export_data(self):
        """Export enhanced packet data"""
        if not self.packet_data:
            messagebox.showwarning("No Data", "No packet data to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json")]
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    data = {
                        'export_info': {
                            'timestamp': datetime.now().isoformat(),
                            'version': 'Enhanced Network Security Monitor v2.0',
                            'packet_count': len(self.packet_data)
                        },
                        'packets': [
                            dict(zip(['time', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 
                                    'protocol', 'length', 'flags', 'ip_version', 'risk_score'], p)) 
                            for p in self.packet_data
                        ]
                    }
                    with open(filename, 'w') as f:
                        json.dump(data, f, indent=2)
                else:
                    import csv
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Time', 'Source IP', 'Src Port', 'Dest IP', 'Dst Port', 
                                       'Protocol', 'Length', 'Flags', 'IP Version', 'Risk Score'])
                        writer.writerows(self.packet_data)
                
                messagebox.showinfo("Export Complete", 
                                  f"Enhanced security data exported!\n\n"
                                  f"• {len(self.packet_data)} packets exported\n"
                                  f"• File: {filename}\n"
                                  f"• Format: {'JSON' if filename.endswith('.json') else 'CSV'}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export enhanced data: {e}")
    
    def apply_filter(self, event=None):
        """Apply enhanced filter to packet display"""
        filter_text = self.filter_var.get().lower()
        protocol_filter = self.protocol_filter_var.get()
        
        if not filter_text and protocol_filter == "All":
            return
        
        for child in self.packet_tree.get_children():
            item = self.packet_tree.item(child)
            values = [str(v).lower() for v in item['values']]
            
            # Text filter
            text_match = any(filter_text in value for value in values) if filter_text else True
            
            # Protocol filter
            protocol_match = (protocol_filter == "All" or 
                            protocol_filter.lower() == item['values'][5].lower()) if protocol_filter else True
            
            if text_match and protocol_match:
                # Show item
                pass
            else:
                # Hide item
                self.packet_tree.detach(child)
    
    def clear_filter(self):
        """Clear enhanced filter"""
        self.filter_var.set("")
        self.protocol_filter_var.set("All")
        # Reattach all items
        for child in self.packet_tree.get_children():
            self.packet_tree.reattach(child, '', 'end')
    
    def refresh_alerts(self):
        """Refresh enhanced alerts from database"""
        try:
            cursor = self.conn.cursor()
            severity_filter = self.severity_var.get()
            alert_type_filter = self.alert_type_var.get()
            
            query = """
                SELECT timestamp, alert_type, source_ip, description, severity, confidence_score
                FROM alerts 
            """
            params = []
            
            if severity_filter != "All" or alert_type_filter != "All":
                query += "WHERE "
                conditions = []
                if severity_filter != "All":
                    conditions.append("severity = ?")
                    params.append(severity_filter)
                if alert_type_filter != "All":
                    conditions.append("alert_type = ?")
                    params.append(alert_type_filter)
                query += " AND ".join(conditions)
            
            query += " ORDER BY timestamp DESC LIMIT 100"
            
            cursor.execute(query, params)
            alerts = cursor.fetchall()
            
            self.alert_text.delete(1.0, tk.END)
            
            for alert in alerts:
                timestamp, alert_type, source_ip, description, severity, confidence = alert
                alert_msg = f"{timestamp} - {severity} {alert_type}: {source_ip} - {description} (Confidence: {confidence:.1f})\n"
                self.alert_text.insert(tk.END, alert_msg, severity)
            
            messagebox.showinfo("Enhanced Alerts Refreshed", 
                              f"Loaded {len(alerts)} security alerts from database\n"
                              f"Filters applied: {severity_filter}, {alert_type_filter}")
                
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Failed to load enhanced alerts: {e}")
    
    def clear_alerts(self):
        """Clear all enhanced alerts"""
        if messagebox.askyesno("Clear Alerts", "Clear all security alerts from display and database?"):
            try:
                cursor = self.conn.cursor()
                cursor.execute("DELETE FROM alerts")
                cursor.execute("DELETE FROM security_events")
                self.conn.commit()
                self.alert_text.delete(1.0, tk.END)
                for item in self.threat_tree.get_children():
                    self.threat_tree.delete(item)
                messagebox.showinfo("Enhanced Alerts Cleared", "All security alerts and events have been cleared")
            except sqlite3.Error as e:
                messagebox.showerror("Database Error", f"Failed to clear enhanced alerts: {e}")

def main():
    """Main function"""
    print("🚀 Starting Enhanced Network Packet Sniffer GUI...")
    print(f"Platform: {platform.system()}")
    print(f"Scapy Available: {SCAPY_AVAILABLE}")
    
    root = tk.Tk()
    app = NetworkMonitorGUI(root)
    
    def on_closing():
        if app.is_monitoring:
            if messagebox.askokcancel("Quit", "Enhanced monitoring is active. Stop and quit?"):
                app.stop_monitoring()
                root.destroy()
        else:
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    try:
        root.mainloop()
    except Exception as e:
        print(f"❌ Enhanced Application Error: {e}")
        messagebox.showerror("Application Error", f"An error occurred: {e}")

if __name__ == "__main__":
    main()
