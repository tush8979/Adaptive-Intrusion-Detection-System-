from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import joblib

model = joblib.load("model/live_ids_model.pkl")
scaler = joblib.load("model/live_scaler.pkl")

packet_count = 0
malicious = 0

def extract_features(packet):
    protocol = 1 if TCP in packet else 2 if UDP in packet else 0
    packet_size = len(packet)
    response_size = packet[IP].len if IP in packet else 0
    return [protocol, packet_size, response_size]

def detect(packet):
    global packet_count, malicious
    if IP in packet:
        packet_count += 1
        df = pd.DataFrame(
            [extract_features(packet)],
            columns=["protocol","packet_size","response_size"]
        )
        pred = model.predict(scaler.transform(df))[0]
        if pred == 1:
            malicious += 1
            print("🚨 Malicious traffic detected")
        else:
            print("✅ Normal traffic")

print("🔍 Live IDS started... CTRL+C to stop")
sniff(prn=detect, store=False)