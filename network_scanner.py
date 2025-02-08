from scapy.all import ARP, Ether, srp
import socket
import ipaddress
import requests
import platform
import subprocess

def get_local_ip():
    """Get the local machine's IP address"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to be reachable
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

def get_manufacturer(mac):
    """Look up manufacturer from MAC address"""
    try:
        # Use the MAC Address IO API
        mac = mac.replace(':', '')
        url = f"https://api.macaddress.io/v1?apiKey=at_YOUR_API_KEY&output=json&search={mac}"
        response = requests.get(url)
        if response.status_code == 200:
            return response.json().get('vendorDetails', {}).get('companyName', 'Unknown')
    except:
        pass
    return 'Unknown'

def ping_host(ip):
    """Ping the host to get its status"""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=1)
        return True
    except:
        return False

def get_device_info(ip, mac):
    """Get additional information about a device"""
    # Get vendor from MAC address (first 6 characters)
    vendor_mac = mac.replace(':', '').upper()[:6]
    
    # Extended list of common ports and their services
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
    
    open_ports = []
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)  # Quick timeout for faster scanning
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(f"{port} ({common_ports[port]})")
        sock.close()
    
    return {
        'vendor': vendor_mac,
        'open_ports': open_ports,
        'is_router': ip.endswith('.1'),
        'hostname': socket.getfqdn(ip)
    }

def scan_network():
    # Get local IP and create network addresses for both common subnets
    local_ip = get_local_ip()
    networks = ['192.168.0.0/24', '192.168.1.0/24']
    
    print(f"Scanning networks: {', '.join(networks)}")
    devices = []
    
    for network in networks:
        # Create ARP request packet
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        try:
            print(f"\nScanning {network}...")
            # Increase timeout and retry count
            result = srp(packet, timeout=5, retry=2, verbose=1)[0]
            
            print("\nProcessing responses...")
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc
                print(f"\nAnalyzing device: {ip}")
                
                device_info = get_device_info(ip, mac)
                devices.append({
                    'ip': ip,
                    'mac': mac,
                    'vendor': device_info['vendor'],
                    'hostname': device_info['hostname'],
                    'open_ports': device_info['open_ports'],
                    'is_router': device_info['is_router']
                })
                
                print(f"Found device: {ip} ({mac})")
                print(f"Vendor MAC: {device_info['vendor']}")
                if device_info['open_ports']:
                    print(f"Open ports: {', '.join(device_info['open_ports'])}")
                    
        except Exception as e:
            print(f"Error scanning network {network}: {e}")
    
    # Additional targeted scans for known IP ranges
    known_ranges = [
        (1, 20),    # Common device IPs
        (100, 110), # Common device IPs
        (254, 255)  # Broadcast and special addresses
    ]
    
    for start, end in known_ranges:
        for last_octet in range(start, end + 1):
            for subnet in ['192.168.0', '192.168.1']:
                ip = f"{subnet}.{last_octet}"
                if ip not in [d['ip'] for d in devices]:
                    print(f"\nTrying additional scan for {ip}...")
                    targeted_arp = ARP(pdst=ip)
                    targeted_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/targeted_arp
                    targeted_result = srp(targeted_packet, timeout=1, verbose=0)[0]
                    
                    if targeted_result:
                        received = targeted_result[0][1]
                        mac = received.hwsrc
                        device_info = get_device_info(ip, mac)
                        devices.append({
                            'ip': ip,
                            'mac': mac,
                            'vendor': device_info['vendor'],
                            'hostname': device_info['hostname'],
                            'open_ports': device_info['open_ports'],
                            'is_router': device_info['is_router']
                        })
                        print(f"Found additional device: {ip} ({mac})")
    
    return devices

def main():
    print("Network Scanner Starting...")
    devices = scan_network()
    
    if devices:
        print("\nDetailed Device Information:")
        print("-" * 80)
        for device in devices:
            print(f"\nDevice at {device['ip']}")
            print(f"MAC Address: {device['mac']}")
            print(f"Vendor MAC: {device['vendor']}")
            print(f"Hostname: {device['hostname']}")
            if device['open_ports']:
                print(f"Open ports: {', '.join(device['open_ports'])}")
            print(f"Type: {'Router' if device['is_router'] else 'Device'}")
            print("-" * 40)
    else:
        print("No devices found.")

if __name__ == "__main__":
    main() 