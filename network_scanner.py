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
    
    # Common ports and their services
    common_ports = {
        80: 'HTTP (Web Server)',
        443: 'HTTPS',
        22: 'SSH',
        21: 'FTP',
        8080: 'HTTP Alternate'
    }
    
    open_ports = []
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
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
    # Get local IP and create network address
    local_ip = get_local_ip()
    network = str(ipaddress.IPv4Network(f"{local_ip}/24", strict=False))
    
    print(f"Scanning network: {network}")
    
    # Create ARP request packet
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    try:
        print("Sending ARP requests...")
        # Increase timeout and retry count
        result = srp(packet, timeout=10, retry=3, verbose=1)[0]
        
        devices = []
        
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
        
        # Additional scan for known IPs that didn't respond
        known_ips = ['192.168.1.101', '192.168.1.102', '192.168.1.105']
        found_ips = [device['ip'] for device in devices]
        
        for ip in known_ips:
            if ip not in found_ips:
                print(f"\nTrying additional scan for {ip}...")
                # Create targeted ARP request
                targeted_arp = ARP(pdst=ip)
                targeted_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/targeted_arp
                targeted_result = srp(targeted_packet, timeout=2, verbose=0)[0]
                
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
    
    except Exception as e:
        if "Permission denied" in str(e):
            print("Error: Root privileges required!")
            print("Please run the script with sudo:")
            print("sudo python network_scanner.py")
        else:
            print(f"An error occurred: {e}")
        return []

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