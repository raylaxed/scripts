import json
import matplotlib.pyplot as plt
from datetime import datetime
import pandas as pd

def load_network_log(filename='network_log.json'):
    data = []
    with open(filename, 'r') as f:
        for line in f:
            if line.strip():
                data.append(json.loads(line))
    return data

def visualize_traffic(data, top_n=5):
    # Convert to DataFrame for easier manipulation
    rows = []
    for entry in data:
        stats = entry['traffic_stats']
        for ip, metrics in stats.items():
            rows.append({
                'timestamp': entry['timestamp'],
                'ip': ip,
                'bytes': metrics['bytes'],
                'packets': metrics['packets']
            })
    
    df = pd.DataFrame(rows)
    
    # Get top N IPs by total bytes
    top_ips = df.groupby('ip')['bytes'].sum().nlargest(top_n).index
    
    # Create two subplots
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
    
    # Plot bytes over time
    for ip in top_ips:
        ip_data = df[df['ip'] == ip]
        ax1.plot(ip_data['timestamp'], ip_data['bytes'], label=ip, marker='.')
    
    ax1.set_title('Bytes Transferred Over Time')
    ax1.set_xlabel('Time')
    ax1.set_ylabel('Bytes')
    ax1.legend(title='IP Address')
    ax1.grid(True)
    
    # Plot packets over time
    for ip in top_ips:
        ip_data = df[df['ip'] == ip]
        ax2.plot(ip_data['timestamp'], ip_data['packets'], label=ip, marker='.')
    
    ax2.set_title('Packets Transferred Over Time')
    ax2.set_xlabel('Time')
    ax2.set_ylabel('Packets')
    ax2.legend(title='IP Address')
    ax2.grid(True)
    
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    data = load_network_log()
    visualize_traffic(data) 