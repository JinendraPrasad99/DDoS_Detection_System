from flask import Flask, render_template, request
import threading
from scapy.all import sniff
from prettytable import PrettyTable
from collections import Counter
import time
import joblib
import pandas as pd

app = Flask(__name__)

# Load the trained model and label encoders
model = joblib.load('ddos_model2.pkl')
label_encoders = joblib.load('label_encoders2.pkl')

# Global variables to store captured packets
packets = []
stored_packets = []

# DDoS detection parameters
DDOS_DETECTED = False
suspected_ips = []
ddos_detection_time = None

# List of IP addresses to ignore
IGNORE_IPS = ['192.168.120.7', '192.168.120.2', '192.168.56.1']

# Function to capture and process packets
def capture_packets():
    global packets
    sniff(prn=process_packet, store=False, iface='eth0')

# Function to process each packet
def process_packet(packet):
    global packets, stored_packets
    
    current_time = time.time()
    packets.append((packet, current_time))
    stored_packets.append((packet, current_time))
    
    # Remove packets older than 300 seconds
    packets = [(pkt, timestamp) for pkt, timestamp in packets if current_time - timestamp <= 300]

# Function to analyze stored packets for DDoS attacks
def analyze_packets():
    global stored_packets, DDOS_DETECTED, suspected_ips, ddos_detection_time
    
    while True:
        time.sleep(60)
        
        try:
            source_ips = [pkt['IP'].src for pkt, _ in stored_packets if pkt.haslayer('IP') and pkt['IP'].src not in IGNORE_IPS]
            source_ip_counts = Counter(source_ips)
            
            DDOS_DETECTED = False
            suspected_ips = []
            
            # TCP SYN Flood attack detection
            if sum(source_ip_counts.values()) > 20:
                for ip, count in source_ip_counts.items():
                    if count > 20:
                        DDOS_DETECTED = True
                        suspected_ips.append(ip)
            
            # UDP Flooding attack detection
            if len([pkt for pkt, _ in stored_packets if pkt.haslayer('UDP')]) > 10:
                DDOS_DETECTED = True
            
            # LAND attack detection
            if len([pkt for pkt, _ in stored_packets if pkt.haslayer('TCP') and pkt['IP'].src == pkt['IP'].dst]) > 1:
                DDOS_DETECTED = True
            
            # SMURF attack detection
            for pkt, _ in stored_packets:
                if pkt.haslayer('ICMP') and pkt['ICMP'].type == 8 and pkt['IP'].dst.endswith('.255'):
                    DDOS_DETECTED = True
                    break
            
            for ip, count in source_ip_counts.items():
                if count > 20:
                    DDOS_DETECTED = True
                    suspected_ips.append(ip)
                    ddos_detection_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
                    break
                    
            # Extract features from packets
            features = extract_features(stored_packets)
            
            if features is not None and not features.empty:
                print("Features extracted:", features.head())
                
                # Apply label encoders
                for column, le in label_encoders.items():
                    if column in features:
                        features[column] = le.transform(features[column])
                
                # Ensure the features match the training features
                required_columns = model.feature_names_in_
                for column in required_columns:
                    if column not in features:
                        features[column] = 0
                
                # Predict using the model
                predictions = model.predict(features[required_columns])
                print("Predictions:", predictions)
                
                if any(predictions):
                    DDOS_DETECTED = True
                    ddos_detection_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
                    suspected_ips = [pkt['IP'].src for pkt, _ in stored_packets if pkt.haslayer('IP') and pkt['IP'].src not in IGNORE_IPS]
                    break
        
        except Exception as e:
            print("Error during packet analysis:", e)

# Function to extract features from packets
def extract_features(packets):
    if not packets:
        return None
    
    features = []
    for packet, _ in packets:
        if packet.haslayer('IP'):
            ip_src = packet['IP'].src
            ip_dst = packet['IP'].dst
            proto = packet.proto
            length = len(packet)
            features.append([ip_src, ip_dst, proto, length])
    
    # Convert to DataFrame and process
    df = pd.DataFrame(features, columns=['ip_src', 'ip_dst', 'proto', 'length'])
    
    return df

# Function to display packets in a table format
def display_packets():
    global packets
    while True:
        if packets:
            table = PrettyTable(['Source IP', 'Count'])
            source_ips = [pkt['IP'].src for pkt, _ in packets if pkt.haslayer('IP') and pkt['IP'].src not in IGNORE_IPS]
            source_ip_counts = Counter(source_ips)
            for ip, count in source_ip_counts.items():
                table.add_row([ip, count])
            app.config['table'] = table.get_html_string()
            packets = []
        else:
            app.config['table'] = "<p>No packets captured yet...</p>"
        time.sleep(5)

capture_thread = threading.Thread(target=capture_packets)
capture_thread.daemon = True
capture_thread.start()

analyze_thread = threading.Thread(target=analyze_packets)
analyze_thread.daemon = True
analyze_thread.start()

display_thread = threading.Thread(target=display_packets)
display_thread.daemon = True
display_thread.start()

@app.route('/')
def index():
    global DDOS_DETECTED, ddos_detection_time
    if DDOS_DETECTED:
        return render_template('index.html', table=app.config['table'], ddos_detected=True, detection_time=ddos_detection_time)
    else:
        return render_template('index.html', table=app.config['table'], ddos_detected=False)

@app.route('/suspicious_ips')
def suspicious_ips():
    return render_template('suspicious_ips.html', suspected_ips=suspected_ips)

if __name__ == '__main__':
    app.run(debug=True)
