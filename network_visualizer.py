import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict
import re
import json
from typing import Dict, Set, Tuple
import matplotlib.colors as mcolors
import os
import random
import math
from datetime import datetime, timedelta
import time

def parse_packet_line(line: str) -> Tuple[str, str]:
    """Parse a packet capture line to extract source and destination."""
    pattern = r"(?:Router|Unknown|AWS)\(([\d\.]+)\) -> (?:Router|Unknown|AWS)\(([\d\.]+)\)"
    match = re.search(pattern, line)
    if match:
        return match.group(1), match.group(2)
    return None, None

def categorize_ip(ip: str) -> str:
    """Categorize IP addresses into types."""
    if ip.startswith('192.168.'):
        return 'Local Device'
    elif 'amazonaws.com' in ip or any(aws_ip in ip for aws_ip in ['34.', '52.', '3.', '13.', '15.', '18.']):
        return 'AWS'
    elif any(cloud_ip in ip for cloud_ip in ['35.', '104.', '172.']):
        return 'Google Cloud'
    elif any(cf_ip in ip for cf_ip in ['162.159.', '172.67.']):
        return 'Cloudflare'
    return 'External Server'

def create_network_graph(packet_capture_file: str = 'packet_capture.json'):
    """Create a network graph from packet capture data."""
    G = nx.Graph()
    connections = defaultdict(set)
    traffic_volume = defaultdict(int)
    protocols = defaultdict(set)  # Track protocols for each connection
    services = defaultdict(set)   # Track services for each connection
    
    # Read and parse the packet capture file
    try:
        with open(packet_capture_file, 'r') as f:
            try:
                packet_data = json.load(f)
                print(f"\nProcessing {len(packet_data)} packets...")
                
                for packet in packet_data:
                    src_ip = packet.get('src')
                    dst_ip = packet.get('dst')
                    size = packet.get('size', 0)
                    protocol = packet.get('protocol', 'Unknown')
                    service = packet.get('service', 'Unknown')
                    
                    if src_ip and dst_ip:
                        connections[src_ip].add(dst_ip)
                        traffic_volume[src_ip] += size
                        traffic_volume[dst_ip] += size
                        
                        # Track protocols and services for each connection
                        key = tuple(sorted([src_ip, dst_ip]))
                        protocols[key].add(protocol)
                        if service != 'Unknown':
                            services[key].add(service)
                        
                        # Add edge with protocol and service information
                        if not G.has_edge(src_ip, dst_ip):
                            G.add_edge(src_ip, dst_ip, protocols=set(), services=set())
                        G[src_ip][dst_ip]['protocols'].add(protocol)
                        if service != 'Unknown':
                            G[src_ip][dst_ip]['services'].add(service)
                        
            except json.JSONDecodeError:
                print("Error: Could not parse packet_capture.json")
                return None, None, None, None, None
    except FileNotFoundError:
        print("Error: Could not find packet_capture.json")
        return None, None, None, None, None
    
    # Print protocol and service statistics
    print("\nProtocol Statistics:")
    protocol_counts = defaultdict(int)
    service_counts = defaultdict(int)
    for edge_protocols in protocols.values():
        for protocol in edge_protocols:
            protocol_counts[protocol] += 1
    for edge_services in services.values():
        for service in edge_services:
            service_counts[service] += 1
            
    for protocol, count in sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{protocol}: {count} connections")
    
    print("\nService Statistics:")
    for service, count in sorted(service_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{service}: {count} connections")
    
    # Rest of the function remains the same
    local_devices = {ip: vol for ip, vol in traffic_volume.items() if ip.startswith('192.168.')}
    most_active_ip = max(local_devices.items(), key=lambda x: x[1])[0] if local_devices else None
    
    print(f"\nMost active device: {most_active_ip}")
    print("Traffic volumes for local devices:")
    for ip, volume in sorted(local_devices.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip}: {volume/1024/1024:.2f} MB")
    
    colors = []
    node_types = {}
    
    color_map = {
        'Local Device': '#ff7f0e',
        'AWS': '#1f77b4',
        'Google Cloud': '#2ca02c',
        'Cloudflare': '#d62728',
        'External Server': '#9467bd'
    }
    
    for ip in set().union(*[{src}.union(dsts) for src, dsts in connections.items()]):
        node_type = categorize_ip(ip)
        G.add_node(ip, node_type=node_type)
        node_types[ip] = node_type
        colors.append(color_map[node_type])
    
    node_degrees = dict(G.degree())
    highly_connected = {node: degree for node, degree in node_degrees.items() 
                       if degree > 20}
    
    print("\nHighly connected nodes (>20 connections):")
    for node, degree in sorted(highly_connected.items(), key=lambda x: x[1], reverse=True):
        node_type = node_types[node]
        print(f"{node} ({node_type}): {degree} connections")
    
    return G, colors, node_types, most_active_ip, node_degrees

def get_next_image_number():
    """Get the next available image number in the network_graphs folder."""
    if not os.path.exists('network_graphs'):
        os.makedirs('network_graphs')
    
    existing_files = os.listdir('network_graphs')
    numbers = [int(f.split('_')[-1].split('.')[0]) 
              for f in existing_files 
              if f.startswith('network_') and f.endswith('.png')]
    
    return max(numbers, default=0) + 1 if numbers else 1

def get_structured_positions(G, node_types, most_active_ip):
    """Create a structured layout with deterministic positions."""
    pos = {}
    
    # Fixed positions for local devices in a pentagon formation
    local_positions = {
        '192.168.1.1': (0, 0),          # Router in center
        '192.168.1.102': (0, 2),        # Your device at top
        '192.168.1.100': (-2, 0),       # Left
        '192.168.1.103': (2, 0),        # Right
        '192.168.1.255': (0, -2)        # Bottom
    }
    
    # Group nodes by type
    nodes_by_type = {
        'Local Device': [],
        'AWS': [],
        'Google Cloud': [],
        'Cloudflare': [],
        'External Server': []
    }
    
    for node in G.nodes():
        nodes_by_type[node_types[node]].append(node)
    
    # Set positions for local devices
    for node in nodes_by_type['Local Device']:
        if node in local_positions:
            pos[node] = local_positions[node]
        else:
            # If we have any additional local devices, place them in a circle
            angle = len(pos) * (2 * math.pi / 5)
            pos[node] = (1.5 * math.cos(angle), 1.5 * math.sin(angle))
    
    # Place other nodes in concentric circles based on their type
    # AWS nodes in the first circle
    aws_radius = 4
    for i, node in enumerate(nodes_by_type['AWS']):
        angle = i * (2 * math.pi / len(nodes_by_type['AWS']))
        pos[node] = (aws_radius * math.cos(angle), aws_radius * math.sin(angle))
    
    # Google Cloud nodes in the second circle
    gc_radius = 5
    for i, node in enumerate(nodes_by_type['Google Cloud']):
        angle = i * (2 * math.pi / len(nodes_by_type['Google Cloud']))
        pos[node] = (gc_radius * math.cos(angle), gc_radius * math.sin(angle))
    
    # Cloudflare nodes in the third circle
    cf_radius = 6
    for i, node in enumerate(nodes_by_type['Cloudflare']):
        angle = i * (2 * math.pi / len(nodes_by_type['Cloudflare']))
        pos[node] = (cf_radius * math.cos(angle), cf_radius * math.sin(angle))
    
    # External servers in the outer circle
    ext_radius = 7
    for i, node in enumerate(nodes_by_type['External Server']):
        angle = i * (2 * math.pi / len(nodes_by_type['External Server']))
        pos[node] = (ext_radius * math.cos(angle), ext_radius * math.sin(angle))
    
    return pos

def visualize_network(G, colors, node_types, most_active_ip, node_degrees):
    """Visualize the network graph."""
    try:
        plt.figure(figsize=(12, 12))
        pos = get_structured_positions(G, node_types, most_active_ip)
        
        # Create protocol color map
        protocol_colors = {
            'HTTP': '#1f77b4',     # Blue
            'HTTPS': '#2ca02c',    # Green
            'DNS': '#d62728',      # Red
            'SSH': '#9467bd',      # Purple
            'FTP': '#8c564b',      # Brown
            'SMTP': '#e377c2',     # Pink
            'TCP': '#7f7f7f',      # Gray
            'UDP': '#bcbd22',      # Yellow-green
            'ICMP': '#17becf',     # Cyan
            'Other': '#7f7f7f'     # Gray
        }
        
        # Draw edges with protocol information
        for (u, v) in G.edges():
            protocols = G[u][v].get('protocols', set())
            services = G[u][v].get('services', set())
            
            # Choose color based on protocol/service
            if services:
                # Use the first service for coloring
                service = list(services)[0]
                color = protocol_colors.get(service.split()[0], protocol_colors['Other'])
            elif protocols:
                # Use the first protocol for coloring
                protocol = list(protocols)[0]
                color = protocol_colors.get(protocol, protocol_colors['Other'])
            else:
                color = protocol_colors['Other']
            
            # Draw edge
            width = 0.3 if (node_types[u] == 'Local Device' or node_types[v] == 'Local Device') else 0.1
            nx.draw_networkx_edges(G, pos,
                                 edgelist=[(u, v)],
                                 edge_color=color,
                                 width=width,
                                 alpha=0.4)
        
        # Draw nodes
        for node_type, color in {
            'Local Device': '#ff7f0e',
            'AWS': '#1f77b4',
            'Google Cloud': '#2ca02c',
            'Cloudflare': '#d62728',
            'External Server': '#9467bd'
        }.items():
            node_list = [node for node in G.nodes() if node_types[node] == node_type]
            
            if node_type == 'AWS':
                node_sizes = [min(200, max(50, node_degrees[node] * 2)) for node in node_list]
            else:
                node_sizes = [min(600, max(100, node_degrees[node] * 8)) for node in node_list]
            
            node_sizes = [size * 1.5 if node == most_active_ip else 
                         size * 1.2 if node_types[node] == 'Local Device' else 
                         size for size, node in zip(node_sizes, node_list)]
            
            nx.draw_networkx_nodes(G, pos,
                                 nodelist=node_list,
                                 node_color=color,
                                 node_size=node_sizes,
                                 alpha=1.0 if node_type == 'Local Device' else 0.7)
        
        # Add labels
        labels = {}
        for node in G.nodes():
            if node_types[node] == 'Local Device':
                labels[node] = f"{node}\n({node_degrees[node]} conn.)"
            elif node_degrees[node] > 100:
                services = set()
                for neighbor in G.neighbors(node):
                    if G.has_edge(node, neighbor):
                        services.update(G[node][neighbor].get('services', set()))
                service_str = ', '.join(sorted(services)[:2])  # Show up to 2 services
                labels[node] = f"{node}\n({node_degrees[node]} conn.)\n{service_str}"
        
        nx.draw_networkx_labels(G, pos, labels, font_size=6)
        
        # Add circles
        for radius in [2, 4, 5, 6, 7]:
            circle = plt.Circle((0, 0), radius, fill=False, linestyle='--', alpha=0.2, color='gray')
            plt.gca().add_patch(circle)
        
        plt.gca().set_aspect('equal')
        plt.axis('off')
        
        # Create legend
        legend_elements = [
            plt.Line2D([0], [0], marker='o', color='w',
                      label=category + (" (Your Device)" if most_active_ip and category == "Local Device" else ""),
                      markerfacecolor=color,
                      markersize=8)
            for category, color in {
                'Local Device': '#ff7f0e',
                'AWS': '#1f77b4',
                'Google Cloud': '#2ca02c',
                'Cloudflare': '#d62728',
                'External Server': '#9467bd'
            }.items()
        ]
        
        # Add protocol colors to legend
        legend_elements.extend([
            plt.Line2D([0], [0], color=color, label=f'{protocol}')
            for protocol, color in protocol_colors.items()
            if protocol not in ['Other', 'TCP', 'UDP']  # Only show application protocols
        ])
        
        plt.legend(handles=legend_elements, loc='center left', bbox_to_anchor=(1, 0.5))
        
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        plt.title(f'Network Packet Visualization - {current_time}\n(Node size indicates connections, edge colors show protocols)')
        
        next_number = get_next_image_number()
        filename = f'network_graphs/network_{next_number:03d}.png'
        plt.savefig(filename, dpi=100, bbox_inches='tight')
        print(f"Network visualization saved as '{filename}'")
        plt.close()
        
    except Exception as e:
        print(f"Error during visualization: {e}")
        plt.close('all')

def main():
    """Main function to run visualization."""
    print("Starting network visualization...")
    
    # Create network_graphs directory if it doesn't exist
    if not os.path.exists('network_graphs'):
        os.makedirs('network_graphs')
    
    try:
        print("\nStarting continuous visualization (5-second intervals)")
        print("Press Ctrl+C to stop")
        
        while True:
            current_time = datetime.now().strftime('%H:%M:%S')
            print(f"\n[{current_time}] Creating network visualization...")
            
            # Create and visualize the network graph
            G, colors, node_types, most_active_ip, node_degrees = create_network_graph()
            
            if G is None:
                print("Error: Could not create network graph.")
                time.sleep(5)
                continue
            
            if len(G.nodes()) == 0:
                print("No network connections found in the packet capture.")
            else:
                if len(G.nodes()) > 100:
                    print("Warning: Large number of nodes detected. Visualization might be cluttered.")
                    
                visualize_network(G, colors, node_types, most_active_ip, node_degrees)
                
                # Generate connection statistics
                node_stats = defaultdict(int)
                for node in G.nodes():
                    node_type = node_types[node]
                    node_stats[node_type] += 1
                
                print("\nNetwork Statistics:")
                print("-" * 50)
                for node_type, count in node_stats.items():
                    print(f"{node_type}: {count} devices")
                print(f"Total Connections: {G.number_of_edges()}")
            
            # Wait for 5 seconds before next visualization
            time.sleep(5)
                
    except KeyboardInterrupt:
        print("\nVisualization stopped by user")
        plt.close('all')
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        plt.close('all')

if __name__ == "__main__":
    main() 