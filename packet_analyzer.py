from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.l2 import Ether
from scapy.all import *
from datetime import datetime
import json
import os
import time

class PacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.known_services = {
            '192.168.0.': 'Local Device',
            '192.168.1.': 'Local Device',
            '224.0.0.': 'Multicast',
            '239.255.255.': 'Multicast',
            '34.': 'AWS',
            '52.': 'AWS',
            '3.': 'AWS',
            '13.': 'AWS',
            '18.': 'AWS',
            '35.': 'Google Cloud',
            '104.': 'Google Cloud',
            '172.217.': 'Google',
            '142.250.': 'Google',
            '172.67.': 'Cloudflare',
            '162.159.': 'Cloudflare',
            '104.16.': 'Cloudflare',
            '104.18.': 'Cloudflare',
            '76.223.': 'AWS CloudFront',
            '54.192.': 'AWS CloudFront',
            '54.75.': 'AWS EC2',
            '54.229.': 'AWS EC2',
            '52.84.': 'AWS CloudFront',
            '52.219.': 'AWS S3',
            '52.217.': 'AWS S3',
            '151.101.': 'Fastly CDN',
            '199.232.': 'Fastly CDN',
            '140.82.': 'GitHub',
            '17.': 'Apple',
            '23.': 'Akamai',
            '23.32.': 'Akamai',
            '23.67.': 'Akamai',
            '96.16.': 'Akamai',
            '184.24.': 'Akamai',
            '184.25.': 'Akamai',
            '184.26.': 'Akamai',
            '184.27.': 'Akamai',
            '184.28.': 'Akamai',
            '184.29.': 'Akamai',
            '184.30.': 'Akamai',
            '184.31.': 'Akamai',
            '184.50.': 'Akamai',
            '184.51.': 'Akamai',
            '184.84.': 'Akamai',
            '184.85.': 'Akamai',
            '184.86.': 'Akamai',
            '184.87.': 'Akamai',
            '8.8.8.8': 'Google DNS',
            '8.8.4.4': 'Google DNS',
            '1.1.1.1': 'Cloudflare DNS',
            '1.0.0.1': 'Cloudflare DNS'
        }
        
    def identify_service(self, ip):
        """Look up service from IP address using known prefixes"""
        # First check exact matches
        if ip in self.known_services:
            return self.known_services[ip]
            
        # Then check prefixes
        for prefix, service in self.known_services.items():
            if ip.startswith(prefix):
                return service
                
        # Check for special ranges
        ip_parts = ip.split('.')
        if len(ip_parts) == 4:
            if ip_parts[0] == '10':
                return 'Private Network'
            elif ip_parts[0] == '172' and 16 <= int(ip_parts[1]) <= 31:
                return 'Private Network'
            elif ip_parts[0] == '192' and ip_parts[1] == '168':
                return 'Local Device'
            elif ip_parts[0] == '169' and ip_parts[1] == '254':
                return 'Link Local'
            elif ip_parts[0] == '224':
                return 'Multicast'
            elif ip_parts[0] == '239':
                return 'Multicast'
                
        return 'External Server'
        
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
                    'protocol': self._get_protocol(packet),
                    'ip_info': {
                        'version': packet[IP].version,
                        'ttl': packet[IP].ttl,
                        'tos': packet[IP].tos,  # Type of Service
                        'id': packet[IP].id,    # IP ID
                        'frag': packet[IP].frag, # Fragmentation
                        'len': packet[IP].len    # Total Length
                    }
                }
                
                # Add detailed protocol information
                if TCP in packet:
                    packet_info.update({
                        'transport_protocol': 'TCP',
                        'sport': packet[TCP].sport,
                        'dport': packet[TCP].dport,
                        'flags': self._get_tcp_flags(packet[TCP]),
                        'service': self._identify_service_by_port(packet[TCP].dport),
                        'tcp_info': {
                            'seq': packet[TCP].seq,      # Sequence number
                            'ack': packet[TCP].ack,      # Acknowledgment number
                            'window': packet[TCP].window, # Window size
                            'urgptr': packet[TCP].urgptr, # Urgent pointer
                            'options': self._get_tcp_options(packet[TCP])
                        }
                    })
                elif UDP in packet:
                    packet_info.update({
                        'transport_protocol': 'UDP',
                        'sport': packet[UDP].sport,
                        'dport': packet[UDP].dport,
                        'service': self._identify_service_by_port(packet[UDP].dport),
                        'udp_info': {
                            'len': packet[UDP].len  # UDP length
                        }
                    })
                elif ICMP in packet:
                    packet_info.update({
                        'transport_protocol': 'ICMP',
                        'type': packet[ICMP].type,
                        'code': packet[ICMP].code,
                        'icmp_info': {
                            'type_name': self._get_icmp_type_name(packet[ICMP].type, packet[ICMP].code),
                            'id': packet[ICMP].id if hasattr(packet[ICMP], 'id') else None,
                            'seq': packet[ICMP].seq if hasattr(packet[ICMP], 'seq') else None
                        }
                    })
                
                # DNS information if present
                if packet.haslayer(DNS):
                    dns_info = self._get_dns_info(packet[DNS])
                    if dns_info:
                        packet_info['dns_info'] = dns_info
                
                # HTTP/HTTPS information if present
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    packet_info['payload_size'] = len(payload)
                    http_info = self._get_http_info(payload)
                    if http_info:
                        packet_info['http_info'] = http_info
                    else:
                        # Only show payload preview if not HTTP
                        packet_info['payload_preview'] = payload[:100].hex()
                
                # Add timing information
                packet_info['time_info'] = {
                    'timestamp': timestamp,
                    'epoch': time.time(),
                    'relative_time': time.time() - self.start_time if hasattr(self, 'start_time') else 0
                }
                
                self.packets.append(packet_info)
                print(f"Packet #{len(self.packets)}: {packet_info['src_service']}({packet_info['src']}) -> "
                      f"{packet_info['dst_service']}({packet_info['dst']}), "
                      f"Size: {packet_info['size']} bytes, "
                      f"Protocol: {packet_info['protocol']}")
                
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def _get_protocol(self, packet):
        """Get detailed protocol information"""
        if TCP in packet:
            dport = packet[TCP].dport
            sport = packet[TCP].sport
            # Check for common application protocols
            if dport == 80 or sport == 80:
                return 'HTTP'
            elif dport == 443 or sport == 443:
                return 'HTTPS'
            elif dport == 53 or sport == 53:
                return 'DNS (TCP)'
            elif dport == 22 or sport == 22:
                return 'SSH'
            elif dport == 21 or sport == 21:
                return 'FTP'
            return 'TCP'
        elif UDP in packet:
            dport = packet[UDP].dport
            sport = packet[UDP].sport
            if dport == 53 or sport == 53:
                return 'DNS'
            elif dport == 67 or dport == 68:
                return 'DHCP'
            elif dport == 123:
                return 'NTP'
            return 'UDP'
        elif ICMP in packet:
            return 'ICMP'
        return 'Other'
    
    def _get_tcp_flags(self, tcp):
        """Get TCP flags as a list"""
        flags = []
        if tcp.flags.S:
            flags.append('SYN')
        if tcp.flags.A:
            flags.append('ACK')
        if tcp.flags.F:
            flags.append('FIN')
        if tcp.flags.R:
            flags.append('RST')
        if tcp.flags.P:
            flags.append('PSH')
        if tcp.flags.U:
            flags.append('URG')
        return flags
    
    def _identify_service_by_port(self, port):
        """Identify service based on port number"""
        common_ports = {
            20: 'FTP Data',
            21: 'FTP Control',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            67: 'DHCP Server',
            68: 'DHCP Client',
            69: 'TFTP',
            80: 'HTTP',
            88: 'Kerberos',
            110: 'POP3',
            123: 'NTP',
            137: 'NetBIOS Name',
            138: 'NetBIOS Datagram',
            139: 'NetBIOS Session',
            143: 'IMAP',
            161: 'SNMP',
            162: 'SNMP Trap',
            389: 'LDAP',
            443: 'HTTPS',
            445: 'SMB',
            465: 'SMTPS',
            500: 'ISAKMP',
            514: 'Syslog',
            515: 'LPD/LPR',
            520: 'RIP',
            587: 'SMTP (MSA)',
            631: 'IPP',
            636: 'LDAPS',
            993: 'IMAPS',
            995: 'POP3S',
            1080: 'SOCKS',
            1433: 'MSSQL',
            1434: 'MSSQL Browser',
            1521: 'Oracle',
            1701: 'L2TP',
            1723: 'PPTP',
            1900: 'UPnP',
            3306: 'MySQL',
            3389: 'RDP',
            5060: 'SIP',
            5061: 'SIP (TLS)',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP Alternate',
            8443: 'HTTPS Alternate',
            9000: 'Jenkins',
            9090: 'WebSphere',
            9200: 'Elasticsearch',
            27017: 'MongoDB'
        }
        return common_ports.get(port, f'Port {port}')
    
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

    def _get_tcp_options(self, tcp):
        """Parse TCP options"""
        options = []
        for opt in tcp.options:
            if opt[0] == 'MSS':
                options.append(f'MSS={opt[1]}')
            elif opt[0] == 'SAckOK':
                options.append('SAckOK')
            elif opt[0] == 'Timestamp':
                options.append(f'Timestamp={opt[1]}')
            elif opt[0] == 'WScale':
                options.append(f'WScale={opt[1]}')
        return options
    
    def _get_dns_info(self, dns):
        """Extract DNS information"""
        if dns.qr == 0:  # Query
            return {
                'type': 'query',
                'name': dns.qd.qname.decode() if dns.qd else None,
                'qtype': dns.qd.qtype if dns.qd else None
            }
        else:  # Response
            answers = []
            for i in range(dns.ancount):
                rr = dns.an[i]
                answers.append({
                    'name': rr.rrname.decode(),
                    'type': rr.type,
                    'data': rr.rdata
                })
            return {
                'type': 'response',
                'answers': answers
            }
    
    def _get_http_info(self, payload):
        """Extract HTTP information from payload"""
        try:
            http_data = payload.decode('utf-8', errors='ignore')
            if http_data.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
                # HTTP Request
                first_line = http_data.split('\r\n')[0]
                method, path, version = first_line.split(' ')
                return {
                    'type': 'request',
                    'method': method,
                    'path': path,
                    'version': version
                }
            elif http_data.startswith('HTTP/'):
                # HTTP Response
                first_line = http_data.split('\r\n')[0]
                version, status_code, reason = first_line.split(' ', 2)
                return {
                    'type': 'response',
                    'version': version,
                    'status_code': status_code,
                    'reason': reason
                }
        except:
            return None
    
    def _get_icmp_type_name(self, icmp_type, icmp_code):
        """Get human-readable ICMP type name"""
        icmp_types = {
            0: 'Echo Reply',
            3: {
                0: 'Network Unreachable',
                1: 'Host Unreachable',
                2: 'Protocol Unreachable',
                3: 'Port Unreachable',
                4: 'Fragmentation Required',
                5: 'Source Route Failed',
                6: 'Network Unknown',
                7: 'Host Unknown'
            },
            8: 'Echo Request',
            11: {
                0: 'TTL Expired in Transit',
                1: 'Fragment Reassembly Time Exceeded'
            }
        }
        
        if icmp_type in icmp_types:
            if isinstance(icmp_types[icmp_type], dict):
                return icmp_types[icmp_type].get(icmp_code, f'Type {icmp_type}, Code {icmp_code}')
            return icmp_types[icmp_type]
        return f'Type {icmp_type}, Code {icmp_code}'

if __name__ == "__main__":
    # Requires root privileges
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run with sudo.")
        sys.exit(1)
        
    analyzer = PacketAnalyzer()
    # Common macOS interface names: en0 (WiFi), en1, bridge0, lo0 (loopback)
    analyzer.start_capture(interface="en0")  # Change interface as needed 