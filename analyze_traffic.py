import json

def analyze_youtube_traffic():
    with open('packet_capture.json') as f:
        packets = json.load(f)
    
    youtube_traffic = [p for p in packets if 'Akamai/YouTube' in (p['src_service'], p['dst_service'])]
    total_bytes = sum(p['size'] for p in youtube_traffic)
    print(f"YouTube Traffic: {total_bytes/1024:.2f} KB")

def analyze_aws_traffic():
    with open('packet_capture.json') as f:
        packets = json.load(f)
    
    aws_traffic = [p for p in packets if 'AWS' in (p['src_service'], p['dst_service'])]
    for p in aws_traffic:
        print(f"AWS {p['src']} -> {p['dst']}: {p['size']} bytes")

def analyze_encrypted():
    with open('packet_capture.json') as f:
        packets = json.load(f)
    
    ssl_traffic = [p for p in packets if p.get('dport') == 443 or p.get('sport') == 443]
    
    print(f"\n=== HTTPS Traffic ({len(ssl_traffic)} connections) ===")
    
    # Group by service
    by_service = {}
    for p in ssl_traffic:
        service = p['dst_service'] if p.get('dport') == 443 else p['src_service']
        ip = p['dst'] if p.get('dport') == 443 else p['src']
        
        if service not in by_service:
            by_service[service] = {
                'bytes': 0,
                'packets': 0,
                'ips': set()
            }
        
        by_service[service]['bytes'] += p['size']
        by_service[service]['packets'] += 1
        by_service[service]['ips'].add(ip)
    
    for service, stats in by_service.items():
        print(f"\n{service}:")
        print(f"  Traffic: {stats['bytes']/1024:.2f} KB in {stats['packets']} packets")
        print(f"  IPs: {sorted(stats['ips'])}")

def analyze_local_network():
    with open('packet_capture.json') as f:
        packets = json.load(f)
    
    local = [p for p in packets if p['src'].startswith('192.168')]
    by_device = {}
    for p in local:
        by_device[p['src']] = by_device.get(p['src'], 0) + p['size']
    
    for ip, bytes in by_device.items():
        print(f"{ip}: {bytes/1024:.2f} KB")

def analyze_unknown_traffic():
    with open('packet_capture.json') as f:
        packets = json.load(f)
    
    unknown = [p for p in packets if 'Unknown' in (p['src_service'], p['dst_service'])]
    by_ip = {}
    
    for p in unknown:
        ip = p['src'] if p['src_service'] == 'Unknown' else p['dst']
        if ip not in by_ip:
            by_ip[ip] = {
                'bytes': 0,
                'packets': 0,
                'ports': set()
            }
        by_ip[ip]['bytes'] += p['size']
        by_ip[ip]['packets'] += 1
        if 'dport' in p:
            by_ip[ip]['ports'].add(p['dport'])
        if 'sport' in p:
            by_ip[ip]['ports'].add(p['sport'])
    
    print("\n=== Unknown Traffic ===")
    for ip, stats in by_ip.items():
        print(f"\nIP: {ip}")
        print(f"Total: {stats['bytes']/1024:.2f} KB in {stats['packets']} packets")
        print(f"Ports: {sorted(stats['ports'])}")

if __name__ == "__main__":
    print("\n=== YouTube Traffic ===")
    analyze_youtube_traffic()
    
    print("\n=== AWS Traffic ===")
    analyze_aws_traffic()
    
    print("\n=== HTTPS Traffic ===")
    analyze_encrypted()
    
    print("\n=== Local Network Usage ===")
    analyze_local_network()
    
    analyze_unknown_traffic() 