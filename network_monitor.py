from network_scanner import scan_network
from scapy.all import sniff, IP, TCP, UDP
import time
from datetime import datetime
import json
from collections import defaultdict
import socket
import os
import sys

class NetworkMonitor:
    def __init__(self, interval=60, output_file="network_log.json"):
        self.interval = interval
        self.output_file = output_file
        self.previous_devices = set()
        self.packet_stats = defaultdict(lambda: {'bytes': 0, 'packets': 0})
        self.seen_destinations = set()
        
        # Ensure the file is writable when created
        try:
            with open(self.output_file, 'a') as f:
                pass
            # Make file writable by all users
            os.chmod(self.output_file, 0o666)
        except Exception as e:
            print(f"Warning: Could not initialize log file: {e}")
        
    def packet_callback(self, packet):
        """Process each captured packet"""
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            length = len(packet)
            
            # Update statistics
            self.packet_stats[src_ip]['bytes'] += length
            self.packet_stats[src_ip]['packets'] += 1
            
            # Log interesting packets (e.g., HTTP, SSH) - but only print new destinations
            if TCP in packet:
                dst_port = packet[TCP].dport
                if dst_port in [80, 443, 22] and dst_ip not in self.seen_destinations:
                    self.seen_destinations.add(dst_ip)
                    service = {80: 'HTTP', 443: 'HTTPS', 22: 'SSH'}[dst_port]
                    try:
                        dst_host = socket.gethostbyaddr(dst_ip)[0]
                    except:
                        dst_host = dst_ip
                    print(f"\nNew {service} connection:")
                    print(f"Destination: {dst_host} ({dst_ip})")

    def monitor_network(self):
        """Monitor network devices and traffic"""
        # Set up logging to both console and file
        log_file = "terminal_log.txt"

        class Logger:
            def __init__(self, filename):
                self.terminal = sys.stdout
                self.log = open(filename, 'a')
                self.log.write(f"\n{'='*80}\nSession started at {datetime.now()}\n{'='*80}\n")
            
            def write(self, message):
                self.terminal.write(message)
                self.log.write(message)
                self.log.flush()
            
            def flush(self):
                self.terminal.flush()
                self.log.flush()

        sys.stdout = Logger(log_file)
        
        print("Network Monitoring Started...")
        
        try:
            while True:
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"\n[{current_time}] Scanning network...")
                
                # Scan for devices
                devices = scan_network()
                current_devices = {(d['ip'], d['mac']) for d in devices}
                
                # Capture packets for a short period
                print("Capturing network traffic...")
                sniff(prn=self.packet_callback, timeout=10)
                
                # Prepare log entry
                log_entry = {
                    'timestamp': current_time,
                    'new_devices': [{'ip': ip, 'mac': mac} for ip, mac in (current_devices - self.previous_devices)],
                    'left_devices': [{'ip': ip, 'mac': mac} for ip, mac in (self.previous_devices - current_devices)],
                    'all_devices': [{'ip': d['ip'], 'mac': d['mac']} for d in devices],
                    'traffic_stats': dict(self.packet_stats)
                }
                
                # Save to file with flush to ensure writing
                try:
                    write_log(log_entry)
                    print(f"Log entry written to {self.output_file}")
                except Exception as e:
                    print(f"Error writing to log file: {e}")
                
                # Print traffic statistics
                print("\nTraffic Statistics:")
                for ip, stats in self.packet_stats.items():
                    print(f"IP: {ip}")
                    print(f"  Bytes: {stats['bytes']}")
                    print(f"  Packets: {stats['packets']}")
                
                self.previous_devices = current_devices
                self.packet_stats.clear()
                
                print(f"\nWaiting {self.interval} seconds until next scan...")
                time.sleep(self.interval)
                
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")
        except Exception as e:
            print(f"\nAn error occurred: {e}")

class LogRotator:
    def __init__(self, base_filename, max_size_mb=50, backup_count=5):
        self.base_filename = base_filename
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.backup_count = backup_count
        self.current_file = None
        
    def should_rotate(self):
        if not os.path.exists(self.base_filename):
            return False
        return os.path.getsize(self.base_filename) >= self.max_size_bytes
        
    def rotate(self):
        if not self.should_rotate():
            return
            
        # Close current file if open
        if self.current_file:
            self.current_file.close()
            self.current_file = None
            
        # Remove oldest backup if it exists
        oldest = f"{self.base_filename}.{self.backup_count}"
        if os.path.exists(oldest):
            os.remove(oldest)
            
        # Rotate existing backups
        for i in range(self.backup_count - 1, 0, -1):
            current = f"{self.base_filename}.{i}"
            if os.path.exists(current):
                os.rename(current, f"{self.base_filename}.{i + 1}")
                
        # Rotate current file
        if os.path.exists(self.base_filename):
            os.rename(self.base_filename, f"{self.base_filename}.1")
            
    def write(self, data):
        """Write data with proper file handling"""
        self.rotate()
        
        try:
            with open(self.base_filename, 'a', buffering=1) as f:
                f.write(json.dumps(data) + '\n')
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
        except Exception as e:
            print(f"Error writing to log: {e}")

def write_log(data, filename='network_log.json'):
    rotator = LogRotator(filename)
    rotator.rotate()
    
    with open(filename, 'a') as f:
        f.write(json.dumps(data) + '\n')

if __name__ == "__main__":
    monitor = NetworkMonitor(interval=30)  # 30 seconds
    monitor.monitor_network() 