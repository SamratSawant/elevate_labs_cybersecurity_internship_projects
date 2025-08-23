"""
Network Packet Sniffer CLI Management Utility
Command-line tool for managing the packet sniffer system
"""

import argparse
import sqlite3
import sys
import os
from datetime import datetime, timedelta
import json
import csv

class SnifferManager:
    """Management utility for the packet sniffer system"""
    
    def __init__(self, db_path="network_monitor.db"):
        self.db_path = db_path
        
        if not os.path.exists(db_path):
            print(f"❌ Database not found: {db_path}")
            print("Initialize with: python db_init.py")
            sys.exit(1)
    
    def get_stats(self, hours=24):
        """Get system statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        since = datetime.now() - timedelta(hours=hours)
        
        print(f"📊 Network Monitor Statistics (Last {hours} hours)")
        print("=" * 60)
        
        # Packet statistics
        cursor.execute("""
            SELECT protocol, COUNT(*) as count, SUM(packet_length) as bytes,
                   COUNT(DISTINCT src_ip) as unique_src_ips,
                   COUNT(DISTINCT dst_ip) as unique_dst_ips
            FROM packets 
            WHERE timestamp > ? 
            GROUP BY protocol 
            ORDER BY count DESC
        """, (since,))
        
        packet_stats = cursor.fetchall()
        
        if packet_stats:
            print("\n🌐 Protocol Distribution:")
            print("Protocol   | Packets   | Bytes      | Src IPs | Dst IPs")
            print("-" * 55)
            total_packets = 0
            total_bytes = 0
            
            for protocol, count, bytes_total, src_ips, dst_ips in packet_stats:
                bytes_str = f"{bytes_total:,}" if bytes_total else "0"
                print(f"{protocol:10} | {count:9,} | {bytes_str:10} | {src_ips:7} | {dst_ips:7}")
                total_packets += count
                total_bytes += bytes_total if bytes_total else 0
                
            print("-" * 55)
            print(f"{'TOTAL':10} | {total_packets:9,} | {total_bytes:10,} |         |        ")
        else:
            print("No packet data found.")
        
        # Alert statistics
        cursor.execute("""
            SELECT alert_type, severity, COUNT(*) as count
            FROM alerts 
            WHERE timestamp > ? 
            GROUP BY alert_type, severity 
            ORDER BY count DESC
        """, (since,))
        
        alert_stats = cursor.fetchall()
        
        if alert_stats:
            print("\n🚨 Security Alerts:")
            print("Alert Type        | Severity | Count")
            print("-" * 40)
            total_alerts = 0
            
            for alert_type, severity, count in alert_stats:
                print(f"{alert_type:17} | {severity:8} | {count:5}")
                total_alerts += count
                
            print("-" * 40)
            print(f"{'TOTAL':17} |          | {total_alerts:5}")
        else:
            print("\nNo alerts found.")
        
        # Top talkers
        cursor.execute("""
            SELECT src_ip, COUNT(*) as packets, SUM(packet_length) as bytes
            FROM packets 
            WHERE timestamp > ? 
            GROUP BY src_ip 
            ORDER BY packets DESC 
            LIMIT 10
        """, (since,))
        
        top_talkers = cursor.fetchall()
        
        if top_talkers:
            print("\n🔝 Top Source IPs:")
            print("IP Address        | Packets   | Bytes")
            print("-" * 40)
            
            for ip, packets, bytes_total in top_talkers:
                bytes_str = f"{bytes_total:,}" if bytes_total else "0"
                print(f"{ip:17} | {packets:9,} | {bytes_str}")
        
        # Traffic timeline
        cursor.execute("""
            SELECT DATE(timestamp) as date, COUNT(*) as packets
            FROM packets 
            WHERE timestamp > ? 
            GROUP BY DATE(timestamp) 
            ORDER BY date DESC
        """, (since,))
        
        timeline = cursor.fetchall()
        
        if timeline and len(timeline) > 1:
            print(f"\n📈 Daily Traffic (Last {min(len(timeline), 7)} days):")
            print("Date       | Packets")
            print("-" * 20)
            
            for date, packets in timeline[:7]:
                print(f"{date} | {packets:8,}")
        
        conn.close()
        print("=" * 60)
    
    def clear_data(self, older_than_days=30):
        """Clear old data from database"""
        cutoff = datetime.now() - timedelta(days=older_than_days)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Count records to be deleted
        cursor.execute("SELECT COUNT(*) FROM packets WHERE timestamp < ?", (cutoff,))
        packet_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp < ?", (cutoff,))
        alert_count = cursor.fetchone()
        
        if packet_count == 0 and alert_count == 0:
            print("✅ No old data to clean up.")
            conn.close()
            return
        
        print(f"🗑️  Will delete:")
        print(f"   • {packet_count:,} packet records")
        print(f"   • {alert_count:,} alert records")
        print(f"   • Older than {older_than_days} days ({cutoff.strftime('%Y-%m-%d')})")
        
        if input("\nContinue? (y/N): ").lower() == 'y':
            cursor.execute("DELETE FROM packets WHERE timestamp < ?", (cutoff,))
            deleted_packets = cursor.rowcount
            
            cursor.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
            deleted_alerts = cursor.rowcount
            
            # Vacuum to reclaim space
            print("🧹 Optimizing database...")
            cursor.execute("VACUUM")
            
            conn.commit()
            
            print(f"✅ Cleanup complete:")
            print(f"   • Deleted {deleted_packets:,} packet records")
            print(f"   • Deleted {deleted_alerts:,} alert records")
        else:
            print("❌ Cancelled.")
        
        conn.close()
    
    def export_data(self, output_file, hours=24, format_type="json"):
        """Export data to file"""
        since = datetime.now() - timedelta(hours=hours)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Export packets
        cursor.execute("""
            SELECT timestamp, src_ip, dst_ip, src_port, dst_port, 
                   protocol, packet_length, flags
            FROM packets 
            WHERE timestamp > ?
            ORDER BY timestamp
        """, (since,))
        
        packets = []
        for row in cursor.fetchall():
            packets.append({
                'timestamp': row[0],
                'src_ip': row[2], 
                'dst_ip': row[3],
                'src_port': row[4],
                'dst_port': row[5],
                'protocol': row[6],
                'length': row[1],
                'flags': row[7]
            })
        
        # Export alerts
        cursor.execute("""
            SELECT timestamp, alert_type, source_ip, target_ip, description, severity
            FROM alerts 
            WHERE timestamp > ?
            ORDER BY timestamp
        """, (since,))
        
        alerts = []
        for row in cursor.fetchall():
            alerts.append({
                'timestamp': row[0],
                'type': row[2],
                'source_ip': row[3],
                'target_ip': row[4],
                'description': row[5],
                'severity': row[6]
            })
        
        # Export data
        if format_type.lower() == "csv":
            self._export_csv(output_file, packets, alerts)
        else:
            self._export_json(output_file, packets, alerts, hours)
        
        print(f"✅ Exported {len(packets):,} packets and {len(alerts):,} alerts to {output_file}")
        conn.close()
    
    def _export_json(self, output_file, packets, alerts, hours):
        """Export data as JSON"""
        data = {
            'export_info': {
                'timestamp': datetime.now().isoformat(),
                'time_range_hours': hours,
                'packet_count': len(packets),
                'alert_count': len(alerts)
            },
            'packets': packets,
            'alerts': alerts
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    def _export_csv(self, output_file, packets, alerts):
        """Export data as CSV (packets only)"""
        with open(output_file, 'w', newline='') as f:
            if packets:
                fieldnames = packets[0].keys()
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(packets)
    
    def show_alerts(self, hours=24, severity=None):
        """Show recent alerts"""
        since = datetime.now() - timedelta(hours=hours)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = """
            SELECT timestamp, alert_type, source_ip, target_ip, description, severity
            FROM alerts 
            WHERE timestamp > ?
        """
        params = [since]
        
        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        
        query += " ORDER BY timestamp DESC LIMIT 50"
        
        cursor.execute(query, params)
        alerts = cursor.fetchall()
        
        if alerts:
            print(f"🚨 Recent Alerts (Last {hours} hours)")
            if severity:
                print(f"   Filtered by severity: {severity}")
            print("=" * 80)
            
            for timestamp, alert_type, source_ip, target_ip, description, sev in alerts:
                # Color coding for severity
                color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(sev, "⚪")
                target_info = f" -> {target_ip}" if target_ip else ""
                
                print(f"{timestamp} {color} {sev:8} {alert_type:15} {source_ip}{target_info}")
                print(f"   {description}")
                print("-" * 80)
        else:
            print("✅ No alerts found.")
        
        conn.close()
    
    def show_sessions(self):
        """Show monitoring sessions"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, start_time, end_time, interface, total_packets, 
                   total_bytes, alerts_generated, status
            FROM sessions 
            ORDER BY start_time DESC 
            LIMIT 20
        """)
        
        sessions = cursor.fetchall()
        
        if sessions:
            print("📋 Recent Monitoring Sessions:")
            print("=" * 80)
            print("ID | Start Time          | Duration    | Interface | Packets  | Alerts | Status")
            print("-" * 80)
            
            for session_id, start_time, end_time, interface, packets, bytes_total, alerts, status in sessions:
                if end_time:
                    start_dt = datetime.fromisoformat(start_time)
                    end_dt = datetime.fromisoformat(end_time)
                    duration = str(end_dt - start_dt).split('.')[0]  # Remove microseconds
                else:
                    duration = "Running..." if status == "ACTIVE" else "Unknown"
                
                packets_str = f"{packets:,}" if packets else "0"
                interface_str = interface[:12] if interface else "Any"
                
                print(f"{session_id:2} | {start_time[:19]} | {duration:11} | {interface_str:9} | {packets_str:8} | {alerts:6} | {status}")
        else:
            print("No sessions found.")
        
        conn.close()
    
    def backup_database(self, backup_path=None):
        """Create database backup"""
        if not backup_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"network_monitor_backup_{timestamp}.db"
        
        try:
            import shutil
            shutil.copy2(self.db_path, backup_path)
            
            # Get database size
            size_mb = os.path.getsize(backup_path) / 1024 / 1024
            
            print(f"✅ Database backed up successfully:")
            print(f"   Source: {self.db_path}")
            print(f"   Backup: {backup_path}")
            print(f"   Size: {size_mb:.2f} MB")
            
        except Exception as e:
            print(f"❌ Backup failed: {e}")

def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description="Network Packet Sniffer Management Utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sniffer_manager.py stats --hours 24
  python sniffer_manager.py export data.json --hours 6
  python sniffer_manager.py cleanup --days 30
  python sniffer_manager.py alerts --severity HIGH
        """
    )
    
    parser.add_argument("--db", default="network_monitor.db", help="Database file path")
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show system statistics')
    stats_parser.add_argument('--hours', type=int, default=24, help='Time window in hours')
    
    # Cleanup command  
    cleanup_parser = subparsers.add_parser('cleanup', help='Clean up old data')
    cleanup_parser.add_argument('--days', type=int, default=30, help='Delete data older than N days')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export data')
    export_parser.add_argument('output', help='Output file name')
    export_parser.add_argument('--hours', type=int, default=24, help='Time window in hours')
    export_parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Export format')
    
    # Alerts command
    alerts_parser = subparsers.add_parser('alerts', help='Show recent alerts')
    alerts_parser.add_argument('--hours', type=int, default=24, help='Time window in hours')
    alerts_parser.add_argument('--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], help='Filter by severity')
    
    # Sessions command
    sessions_parser = subparsers.add_parser('sessions', help='Show monitoring sessions')
    
    # Backup command
    backup_parser = subparsers.add_parser('backup', help='Backup database')
    backup_parser.add_argument('--output', help='Backup file path (optional)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    manager = SnifferManager(args.db)
    
    try:
        if args.command == 'stats':
            manager.get_stats(args.hours)
        elif args.command == 'cleanup':
            manager.clear_data(args.days)
        elif args.command == 'export':
            manager.export_data(args.output, args.hours, args.format)
        elif args.command == 'alerts':
            manager.show_alerts(args.hours, args.severity)
        elif args.command == 'sessions':
            manager.show_sessions()
        elif args.command == 'backup':
            manager.backup_database(args.output)
    except KeyboardInterrupt:
        print("\n🛑 Operation cancelled by user")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
