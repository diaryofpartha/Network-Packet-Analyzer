import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from scapy.all import sniff, Ether
from collections import Counter
import psutil  # For getting network interfaces
import time

# Global variables to store packet counts
packet_counts = Counter()
start_time = time.time()
stop_capture = False
selected_interface = None

def get_network_interfaces():
    """
    Get a list of available network interfaces.
    """
    interfaces = psutil.net_if_addrs().keys()
    return interfaces

def update_graph(frame):
    global packet_counts, start_time, stop_capture
    
    if selected_interface is None:
        return False

    # Get elapsed time
    elapsed_time = time.time() - start_time

    # Sniff packets for 1 second
    sniffed_packets = sniff(timeout=1, iface=selected_interface, count=100)

    # Update packet counts
    for packet in sniffed_packets:
        if Ether in packet:
            packet_counts[packet[Ether].src] += 1

    # Clear the current plot
    plt.clf()

    # Plot the top 10 source MAC addresses
    top_sources = packet_counts.most_common(10)
    sources, counts = zip(*top_sources)
    plt.bar(sources, counts)
    plt.xlabel('Source MAC Address')
    plt.ylabel('Packet Count')
    plt.title('Top 10 Source MAC Addresses (Last 1 second)')
    plt.xticks(rotation=45, ha='right')

    # Adjust the plot layout
    plt.tight_layout()

    # Stop capturing packets if flag is set
    if stop_capture:
        return False

def stop_capture_func(event):
    global stop_capture
    stop_capture = True

# Get available network interfaces
network_interfaces = get_network_interfaces()

if not network_interfaces:
    print("No network interfaces found. Exiting.")
    exit()

# Prompt user to select a network interface
print("Available network interfaces:")
for i, interface in enumerate(network_interfaces, 1):
    print(f"{i}. {interface}")
selection = int(input("Select a network interface: ")) - 1

if selection < 0 or selection >= len(network_interfaces):
    print("Invalid selection. Exiting.")
    exit()

selected_interface = list(network_interfaces)[selection]

# Create a live animation
ani = FuncAnimation(plt.gcf(), update_graph, interval=1000)

# Register event handler for stopping capture
plt.gcf().canvas.mpl_connect('close_event', stop_capture_func)

# Show the plot
plt.show()
