import json
from datetime import datetime

def analyze_logs(log_file="network_log.json"):
    print("Network Log Analysis")
    print("-" * 50)
    
    with open(log_file, 'r') as f:
        logs = [json.loads(line) for line in f]
    
    for entry in logs:
        print(f"\nTimestamp: {entry['timestamp']}")
        print("\nDevices Present:")
        for device in entry['all_devices']:
            print(f"  {device['ip']} ({device['mac']})")
        
        if 'traffic_stats' in entry:
            print("\nTop Traffic Sources:")
            # Sort by bytes
            sorted_traffic = sorted(
                entry['traffic_stats'].items(), 
                key=lambda x: x[1]['bytes'], 
                reverse=True
            )[:5]
            
            for ip, stats in sorted_traffic:
                mb = stats['bytes'] / 1024 / 1024
                print(f"  {ip}: {mb:.2f} MB ({stats['packets']} packets)")
        
        print("-" * 50)

if __name__ == "__main__":
    analyze_logs() 