import pandas as pd
from scapy.all import rdpcap

def extract_features_from_pcap(file):
    packets = rdpcap(file)
    features = []

    for packet in packets:
        if packet.haslayer('IP'):
            dt = packet.time  # Timestamp of the packet
            switch = 1  # Switch identifier
            src = packet['IP'].src  # Source IP address
            dst = packet['IP'].dst  # Destination IP address
            pktcount = 1  # Number of packets (assuming one packet per iteration)
            bytecount = len(packet)  # Size of the packet in bytes
            dur = 0  # Duration of the packet (you may need to calculate this)
            dur_nsec = 0  # Duration in nanoseconds
            tot_dur = 0  # Total duration (you may need to calculate this)
            flows = 0  # Number of flows (you may need to calculate this)
            packetins = 0  # Packet insertion count
            pktperflow = 0  # Packets per flow
            byteperflow = 0  # Bytes per flow
            pktrate = 0  # Packet rate
            Pairflow = 0  # Pair flow
            Protocol = packet['IP'].proto  # Protocol used in the packet
            port_no = 0  # Port number (you may need to extract this from the packet)
            tx_bytes = 0  # Transmitted bytes
            rx_bytes = 0  # Received bytes
            tx_kbps = 0  # Transmitted kilobytes per second
            rx_kbps = 0  # Received kilobytes per second
            tot_kbps = 0  # Total kilobytes per second
            label = 0  # Label for classification (0 for normal traffic)

            # Append the features to the list
            features.append([dt, switch, src, dst, pktcount, bytecount, dur, dur_nsec, tot_dur, flows, packetins,
                             pktperflow, byteperflow, pktrate, Pairflow, Protocol, port_no, tx_bytes, rx_bytes,
                             tx_kbps, rx_kbps, tot_kbps, label])

    return features

#Usage file
normal_traffic_features = extract_features_from_pcap('normal_traffic.pcap')
attack_traffic_features = extract_features_from_pcap('attack_traffic.pcap')

# Combine normal and attack traffic features into a single dataset
all_features = normal_traffic_features + attack_traffic_features

# Create a DataFrame
columns = ['dt', 'switch', 'src', 'dst', 'pktcount', 'bytecount', 'dur', 'dur_nsec', 'tot_dur', 'flows',
           'packetins', 'pktperflow', 'byteperflow', 'pktrate', 'Pairflow', 'Protocol', 'port_no', 'tx_bytes',
           'rx_bytes', 'tx_kbps', 'rx_kbps', 'tot_kbps', 'label']
df = pd.DataFrame(all_features, columns=columns)

# Save the DataFrame to a CSV file
df.to_csv('network_traffic.csv', index=False)
