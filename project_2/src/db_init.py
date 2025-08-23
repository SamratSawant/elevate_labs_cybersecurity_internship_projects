"""
Database initialization script for Network Packet Sniffer
Creates and configures the SQLite database with proper schema
"""

import sqlite3
import os
from datetime import datetime

def init_database(db_path="network_monitor.db"):
    """Initialize the database with proper schema and indexes"""
    
    # Create backup if database exists
    if os.path.exists(db_path):
        backup_path = f"{db_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.rename(db_path, backup_path)
        print(f"Existing database backed up to: {backup_path}")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Enable WAL mode for better performance
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA cache_size=10000")
        cursor.execute("PRAGMA temp_store=MEMORY")
        
        # Create schema
        schema_sql = """
        -- Main packets table
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
            packet_data BLOB
        );
        
        -- Security alerts table
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            alert_type TEXT NOT NULL,
            source_ip TEXT,
            target_ip TEXT,
            description TEXT NOT NULL,
            severity TEXT DEFAULT 'MEDIUM' CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
            resolved BOOLEAN DEFAULT FALSE,
            resolved_at DATETIME,
            resolved_by TEXT
        );
        
        -- Traffic statistics table
        CREATE TABLE traffic_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            protocol TEXT NOT NULL,
            packet_count INTEGER DEFAULT 0,
            byte_count INTEGER DEFAULT 0,
            unique_src_ips INTEGER DEFAULT 0,
            unique_dst_ips INTEGER DEFAULT 0,
            time_window INTEGER DEFAULT 60
        );
        
        -- Configuration table
        CREATE TABLE config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            description TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Session logs table
        CREATE TABLE sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            end_time DATETIME,
            interface TEXT,
            total_packets INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0,
            alerts_generated INTEGER DEFAULT 0,
            status TEXT DEFAULT 'ACTIVE'
        );
        
        -- Performance indexes
        CREATE INDEX idx_packets_timestamp ON packets(timestamp);
        CREATE INDEX idx_packets_src_ip ON packets(src_ip);
        CREATE INDEX idx_packets_dst_ip ON packets(dst_ip);
        CREATE INDEX idx_packets_protocol ON packets(protocol);
        CREATE INDEX idx_alerts_timestamp ON alerts(timestamp);
        CREATE INDEX idx_alerts_type ON alerts(alert_type);
        CREATE INDEX idx_alerts_severity ON alerts(severity);
        CREATE INDEX idx_stats_timestamp ON traffic_stats(timestamp);
        CREATE INDEX idx_config_key ON config(key);
        
        -- Insert default configuration
        INSERT INTO config (key, value, description) VALUES
        ('port_scan_threshold', '20', 'Number of ports scanned before triggering alert'),
        ('flood_threshold', '100', 'Packets per minute threshold for flood detection'),
        ('large_packet_threshold', '1500', 'Packet size threshold in bytes'),
        ('time_window', '60', 'Time window for anomaly detection in seconds'),
        ('email_cooldown', '300', 'Cooldown period between email alerts in seconds'),
        ('max_packets_stored', '100000', 'Maximum packets to store in database'),
        ('auto_cleanup', 'true', 'Enable automatic cleanup of old data'),
        ('cleanup_days', '30', 'Days to keep packet data');
        """
        
        cursor.executescript(schema_sql)
        conn.commit()
        
        print(f"Database initialized successfully: {db_path}")
        print("Tables created:")
        
        # Verify tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        for table in tables:
            print(f"  - {table[0]}")
            
        # Show configuration
        cursor.execute("SELECT key, value, description FROM config")
        configs = cursor.fetchall()
        print("\nDefault configuration:")
        for key, value, desc in configs:
            print(f"  {key}: {value} ({desc})")
        
        return True
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    finally:
        conn.close()

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Initialize Network Monitor Database")
    parser.add_argument("--db", default="network_monitor.db", help="Database file path")
    parser.add_argument("--force", action="store_true", help="Force recreate database")
    
    args = parser.parse_args()
    
    if os.path.exists(args.db) and not args.force:
        response = input(f"Database {args.db} already exists. Recreate? (y/N): ")
        if response.lower() != 'y':
            print("Cancelled.")
            return
    
    success = init_database(args.db)
    if success:
        print("\nDatabase is ready for use!")
        print("You can now run the packet sniffer:")
        print("  python packet_sniffer.py")
        print("  python gui_sniffer.py")
    else:
        print("\nDatabase initialization failed!")

if __name__ == "__main__":
    main()
