import json
import matplotlib.pyplot as plt
from datetime import datetime
import matplotlib.dates as mdates
import os
import numpy as np
from matplotlib.animation import FuncAnimation
import matplotlib
matplotlib.use('Qt5Agg')  # Use Qt5 backend for live plotting

class LiveTrafficMonitor:
    def __init__(self, window_size=10):
        self.window_size = window_size  # Number of data points to show
        self.timestamps = []
        self.total_bytes = []
        self.device_bytes = {}
        
        # Set up the plot
        self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=(20, 12))
        self.fig.suptitle('Live Network Traffic Analysis')
        
        # Create output directory
        os.makedirs('network_graphs', exist_ok=True)

    def update_plot(self, frame):
        try:
            # Read the last line from network_log.json
            with open('network_log.json', 'r') as f:
                lines = f.readlines()
                if lines:
                    data = json.loads(lines[-1])
                    time = datetime.strptime(data['timestamp'], '%Y-%m-%d %H:%M:%S')
                    total = sum(stat['bytes'] for stat in data['traffic_stats'].values())
                    
                    # Update data
                    self.timestamps.append(time)
                    self.total_bytes.append(total)
                    
                    # Keep only last window_size points
                    if len(self.timestamps) > self.window_size:
                        self.timestamps = self.timestamps[-self.window_size:]
                        self.total_bytes = self.total_bytes[-self.window_size:]
                    
                    # Update device data
                    for ip, stats in data['traffic_stats'].items():
                        if ip not in self.device_bytes:
                            self.device_bytes[ip] = []
                        self.device_bytes[ip].append(stats['bytes'])
                        if len(self.device_bytes[ip]) > self.window_size:
                            self.device_bytes[ip] = self.device_bytes[ip][-self.window_size:]
                    
                    # Clear and redraw plots
                    self.ax1.clear()
                    self.ax2.clear()
                    
                    # Plot total traffic
                    self.ax1.plot(self.timestamps, self.total_bytes, 'b-', label='Total Traffic')
                    self.ax1.set_title('Total Network Traffic (Live)')
                    self.ax1.set_ylabel('Bytes')
                    self.ax1.grid(True)
                    self.ax1.legend()
                    
                    # Plot device traffic
                    colors = plt.cm.rainbow(np.linspace(0, 1, len(self.device_bytes)))
                    for (ip, bytes_list), color in zip(self.device_bytes.items(), colors):
                        if len(bytes_list) > 0:  # Only plot if we have data
                            self.ax2.plot(self.timestamps[-len(bytes_list):], 
                                        bytes_list, 
                                        label=f'Device: {ip}', 
                                        alpha=0.7,
                                        color=color)
                    
                    # Format axes
                    for ax in [self.ax1, self.ax2]:
                        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
                        ax.xaxis.set_major_locator(mdates.SecondLocator(interval=30))
                        plt.setp(ax.xaxis.get_majorticklabels(), rotation=45, ha='right')
                    
                    self.ax2.set_title('Device Traffic (Live)')
                    self.ax2.set_xlabel('Time')
                    self.ax2.set_ylabel('Bytes')
                    self.ax2.grid(True)
                    self.ax2.legend(bbox_to_anchor=(1.05, 1), loc='upper left', fontsize='small')
                    
                    plt.tight_layout()
                    
        except Exception as e:
            print(f"Error updating plot: {e}")

    def start_monitoring(self):
        # Update every 5 seconds
        ani = FuncAnimation(self.fig, self.update_plot, interval=5000)
        plt.show()

if __name__ == "__main__":
    monitor = LiveTrafficMonitor(window_size=10)  # Show last 10 data points
    monitor.start_monitoring() 