from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.all import *
from datetime import datetime
import json
import os

class PacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.known_services = {
            '192.168.1.1': 'Router',
            '192.168.1.100': 'Device 1',
            '192.168.1.101': 'Device 2',
            '192.168.1.102': 'Device 3',
            '64.239': 'Akamai/YouTube',
            '172.67': 'Cloudflare',
            '140.82': 'GitHub',
            '17.': 'Apple',
            '34.': 'AWS',
            '3.': 'AWS',
            '13.': 'AWS'
        }
        
    def identify_service(self, ip):
        for prefix, service in self.known_services.items():
            if ip.startswith(prefix):
                return service
        return "Unknown"
        
    def packet_callback(self, packet):
        try:
            if IP in packet:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                
                # Basic packet info
                packet_info = {
                    'timestamp': timestamp,
                    'src': packet[IP].src,
                    'src_service': self.identify_service(packet[IP].src),
                    'dst': packet[IP].dst,
                    'dst_service': self.identify_service(packet[IP].dst),
                    'size': len(packet),
                    'protocol': 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'Other'
                }
                
                # Add port information if available
                if TCP in packet:
                    packet_info.update({
                        'sport': packet[TCP].sport,
                        'dport': packet[TCP].dport
                    })
                elif UDP in packet:
                    packet_info.update({
                        'sport': packet[UDP].sport,
                        'dport': packet[UDP].dport
                    })
                
                # Try to get payload if available
                if packet.haslayer('Raw'):
                    payload = packet[Raw].load
                    packet_info['payload_size'] = len(payload)
                    # Only show first 100 bytes of payload in hex
                    packet_info['payload_preview'] = payload[:100].hex()
                
                self.packets.append(packet_info)
                print(f"Packet #{len(self.packets)}: {packet_info['src_service']}({packet_info['src']}) -> "
                      f"{packet_info['dst_service']}({packet_info['dst']}), "
                      f"Size: {packet_info['size']} bytes, "
                      f"Protocol: {packet_info['protocol']}")
                
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def list_interfaces(self):
        print("\nAvailable interfaces:")
        for iface in get_if_list():
            print(f"- {iface}")
        print()
    
    def start_capture(self, interface=None):
        if not interface:
            self.list_interfaces()
            interface = conf.iface
            
        print(f"Starting packet capture on {interface}...")
        print("Press Ctrl+C to stop capture")
        
        try:
            # Initialize log entry
            log_entry = {
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "traffic_stats": {}
            }
            
            def update_stats():
                # Update traffic statistics
                traffic_stats = {}
                for p in self.packets:
                    src, dst = p['src'], p['dst']
                    for ip in [src, dst]:
                        if ip not in traffic_stats:
                            traffic_stats[ip] = {"bytes": 0, "packets": 0}
                        traffic_stats[ip]["bytes"] += p["size"]
                        traffic_stats[ip]["packets"] += 1
                
                log_entry["traffic_stats"] = traffic_stats
                
                # Save files
                try:
                    with open('packet_capture.json', 'w') as f:
                        json.dump(self.packets, f, indent=2)
                    with open('network_log.json', 'a+') as f:
                        f.write(json.dumps(log_entry) + "\n")
                    print(f"\rCaptured {len(self.packets)} packets", end='')
                except Exception as e:
                    print(f"\nError writing to files: {e}")
            
            # Update stats every 10 packets
            def packet_handler(packet):
                self.packet_callback(packet)
                if len(self.packets) % 10 == 0:
                    update_stats()
            
            # Start capture
            sniff(iface=interface, prn=packet_handler, store=0)
            
        except KeyboardInterrupt:
            print("\nCapture stopped by user")
            update_stats()  # Final update
            
        except Exception as e:
            print(f"Error starting capture: {e}")

if __name__ == "__main__":
    # Requires root privileges
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run with sudo.")
        sys.exit(1)
        
    analyzer = PacketAnalyzer()
    # Common macOS interface names: en0 (WiFi), en1, bridge0, lo0 (loopback)
    analyzer.start_capture(interface="en0")  # Change interface as needed 