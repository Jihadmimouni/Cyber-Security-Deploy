from collections import Counter
import logging
import numpy as np
import ipaddress
from scapy.all import  IP, TCP, UDP, ICMP
from sklearn.preprocessing import StandardScaler


global source_ip 
source_ip= ipaddress.ip_network('192.168.1.15/32')
global destination_ip
destination_ip= ipaddress.ip_network('0.0.0.0/0')
global batchsize 
batchsize = 64

def set_source_ip(ip):
    global source_ip
    source_ip = ip

def set_destination_ip(ip):
    global destination_ip
    global batchsize
    destination_ip = ip

def set_batchsize(size):
    global batchsize
    batchsize = size

def in_subnet(ip, subnet):
    ip_obj = ipaddress.ip_address(ip)
    return ip_obj in subnet

def calculate_protocol(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    protocol_map = {
        "TCP": 6,      # Protocol number for TCP
        "UDP": 17,     # Protocol number for UDP
        "ICMP": 1,     # Protocol number for ICMP
        'Other': 0     # For other protocols, we can leave it as 0
    }
    
    protocol_count = []
    
    for packet in packets[:batchsize]:  # Limit to first batchsize packets
        if packet.haslayer(TCP):
            protocol_count.append(6)
        elif packet.haslayer(UDP):
            protocol_count.append(17)
        elif packet.haslayer(ICMP):
            protocol_count.append(1)
        else:
            protocol_count.append(0)
    
    # Count the occurrences of each protocol
    protocol_counter = Counter(protocol_count)
    
    # Find the most frequent protocol
    dominant_protocol_number = protocol_counter.most_common(1)[0][0]
    
    
    return dominant_protocol_number

def calculate_flow_duration(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    # Get the timestamps of the first and last packet
    first_packet_time = packets[0].time
    last_packet_time = packets[63].time  # Index 63 is the batchsizeth packet
    
    # Calculate flow duration (in seconds)
    flow_duration = last_packet_time - first_packet_time
    return flow_duration

def calculate_total_fwd_packets(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    
    # Count the forward packets (from source_ip to destination_ip)
    fwd_packet_count = 0
    
    for packet in packets[:batchsize]:  # Limit to first batchsize packets
        if packet.haslayer(IP):
            if in_subnet(packet[1].src , source_ip) and in_subnet(packet[1].dst , destination_ip):
                fwd_packet_count += 1
    
    return fwd_packet_count

def calculate_total_bwd_packets(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    
    
    # Count the backward packets (from destination_ip to source_ip)
    bwd_packet_count = 0
    
    for packet in packets[:batchsize]:  # Limit to first batchsize packets
        if packet.haslayer(IP):
            if in_subnet(packet[1].src , destination_ip) and in_subnet(packet[1].dst, source_ip):
                bwd_packet_count += 1
    
    return bwd_packet_count

def calculate_total_length_fwd_packets(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    # Sum the lengths of forward packets (from source_ip to destination_ip)
    total_fwd_length = 0
    
    for packet in packets[:batchsize]:  # Limit to first batchsize packets
        if packet.haslayer(IP):
            if in_subnet(packet[1].src , source_ip) and in_subnet(packet[1].dst , destination_ip):
                total_fwd_length += len(packet)  # Add the length of the forward packet
    
    return total_fwd_length

def calculate_total_length_bwd_packets(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    
    
    # Sum the lengths of backward packets (from destination_ip to source_ip)
    total_bwd_length = 0
    
    for packet in packets[:batchsize]:  # Limit to first batchsize packets
        if packet.haslayer(IP):
            if in_subnet(packet[1].src , destination_ip) and in_subnet(packet[1].dst, source_ip):
                total_bwd_length += len(packet)  # Add the length of the backward packet
    
    return total_bwd_length

def calculate_fwd_packet_length_metrics(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    
    
    # List to store lengths of forward packets
    fwd_lengths = []
    
    for packet in packets[:batchsize]:  # Limit to first batchsize packets
        if packet.haslayer(IP):
            if in_subnet(packet[1].src , source_ip) and in_subnet(packet[1].dst , destination_ip):
                fwd_lengths.append(len(packet))  # Add the length of the forward packet
    
    # If no forward packets were found
    if not fwd_lengths:
        return {
        'Fwd Packet Length Max': 0,
        'Fwd Packet Length Min': 0,
        'Fwd Packet Length Mean': 0,
        'Fwd Packet Length Std': 0
    }
    
    # Calculate the metrics
    fwd_packet_length_max = np.max(fwd_lengths)
    fwd_packet_length_min = np.min(fwd_lengths)
    fwd_packet_length_mean = np.mean(fwd_lengths)
    fwd_packet_length_std = np.std(fwd_lengths)
    
    return {
        'Fwd Packet Length Max': fwd_packet_length_max,
        'Fwd Packet Length Min': fwd_packet_length_min,
        'Fwd Packet Length Mean': fwd_packet_length_mean,
        'Fwd Packet Length Std': fwd_packet_length_std
    }

def calculate_bwd_packet_length_metrics(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    

    
    # List to store lengths of backward packets
    bwd_lengths = []
    
    for packet in packets[:batchsize]:  # Limit to first batchsize packets
        if packet.haslayer(IP):
            if in_subnet(packet[1].src , destination_ip) and in_subnet(packet[1].dst, source_ip):
                bwd_lengths.append(len(packet))  # Add the length of the backward packet
    
    # If no backward packets were found
    if not bwd_lengths:
        return {
        'Bwd Packet Length Max': 0,
        'Bwd Packet Length Min': 0,
        'Bwd Packet Length Mean': 0,
        'Bwd Packet Length Std': 0
    }
    
    # Calculate the metrics
    bwd_packet_length_max = np.max(bwd_lengths)
    bwd_packet_length_min = np.min(bwd_lengths)
    bwd_packet_length_mean = np.mean(bwd_lengths)
    bwd_packet_length_std = np.std(bwd_lengths)
    
    return {
        'Bwd Packet Length Max': bwd_packet_length_max,
        'Bwd Packet Length Min': bwd_packet_length_min,
        'Bwd Packet Length Mean': bwd_packet_length_mean,
        'Bwd Packet Length Std': bwd_packet_length_std
    }

def calculate_flow_bytes_per_second(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    # Assume the first packet defines the flow's start and end packet defines the flow's end
    first_packet = packets[0]
    last_packet = packets[-1]
    
    # Get the time difference between the first and last packet (Flow Duration)
    flow_duration = last_packet.time - first_packet.time
    
    # Calculate the total bytes in the flow (sum of packet lengths)
    total_bytes = sum(len(packet) for packet in packets[:batchsize])  # Limit to the first batchsize packets
    
    # Calculate Flow Bytes/s
    if flow_duration > 0:
        flow_bytes_per_second = total_bytes / flow_duration
    else:
        return 0
    
    return flow_bytes_per_second

def calculate_flow_packets_per_second(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

   
    
    # Assume the first packet defines the flow's start and last packet defines the flow's end
    first_packet = packets[0]
    last_packet = packets[-1]
    
    # Get the time difference between the first and last packet (Flow Duration)
    flow_duration = last_packet.time - first_packet.time
    
    # Calculate the total number of packets in the flow
    total_packets = len(packets[:batchsize])  # Limit to first batchsize packets
    
    # Calculate Flow Packets/s
    if flow_duration > 0:
        flow_packets_per_second = total_packets / flow_duration
    else:
        return 0
    
    return flow_packets_per_second

def calculate_flow_iat_metrics(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    # Extract timestamps of the first batchsize packets
    timestamps = [packet.time for packet in packets[:batchsize]]
    
    # Calculate the inter-arrival times (IAT) between consecutive packets
    iat = np.diff(timestamps)  # Difference between consecutive timestamps
    
    # Calculate IAT metrics
    flow_iat_mean = np.mean(iat)
    flow_iat_std = np.std(iat)
    flow_iat_max = np.max(iat)
    flow_iat_min = np.min(iat)
    
    return {
        'Flow IAT Mean': flow_iat_mean,
        'Flow IAT Std': flow_iat_std,
        'Flow IAT Max': flow_iat_max,
        'Flow IAT Min': flow_iat_min
    }

def calculate_fwd_iat_metrics(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    
    
    
    # List to store timestamps of forward packets
    fwd_timestamps = []
    
    # Collect timestamps of forward packets (packets from source to destination)
    for packet in packets[:batchsize]:
        if packet.haslayer(IP):
            if in_subnet(packet[1].src , source_ip) and in_subnet(packet[1].dst , destination_ip):
                fwd_timestamps.append(packet.time)  # Add timestamp of forward packet
    
    # If no forward packets were found
    if not fwd_timestamps:
        return  {
        'Fwd IAT Total': 0,
        'Fwd IAT Mean': 0,
        'Fwd IAT Std': 0,
        'Fwd IAT Max':0,
        'Fwd IAT Min': 0
    }
    
    # Calculate the inter-arrival times (IAT) for forward packets
    fwd_iat = np.diff(fwd_timestamps)  # Difference between consecutive timestamps
    
    # Calculate Fwd IAT metrics
    fwd_iat_total = np.sum(fwd_iat)
    fwd_iat_mean = np.mean(fwd_iat)
    fwd_iat_std = np.std(fwd_iat)
    fwd_iat_max = np.max(fwd_iat)
    fwd_iat_min = np.min(fwd_iat)
    
    return {
        'Fwd IAT Total': fwd_iat_total,
        'Fwd IAT Mean': fwd_iat_mean,
        'Fwd IAT Std': fwd_iat_std,
        'Fwd IAT Max': fwd_iat_max,
        'Fwd IAT Min': fwd_iat_min
    }

def calculate_bwd_iat_metrics(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    
    
    
    # List to store timestamps of backward packets
    bwd_timestamps = []
    
    # Collect timestamps of backward packets (packets from destination to source)
    for packet in packets[:batchsize]:
        if packet.haslayer(IP):
            if in_subnet(packet[1].src , destination_ip) and in_subnet(packet[1].dst, source_ip):
                bwd_timestamps.append(packet.time)  # Add timestamp of backward packet
    
    # If no backward packets were found
    if not bwd_timestamps:
        return {
        'Bwd IAT Total': 0,
        'Bwd IAT Mean': 0,
        'Bwd IAT Std': 0,
        'Bwd IAT Max': 0,
        'Bwd IAT Min': 0
    }
    
    # Calculate the inter-arrival times (IAT) for backward packets
    bwd_iat = np.diff(bwd_timestamps)  # Difference between consecutive timestamps
    
    # Calculate Bwd IAT metrics
    bwd_iat_total = np.sum(bwd_iat)
    bwd_iat_mean = np.mean(bwd_iat)
    bwd_iat_std = np.std(bwd_iat)
    bwd_iat_max = np.max(bwd_iat)
    bwd_iat_min = np.min(bwd_iat)
    
    return {
        'Bwd IAT Total': bwd_iat_total,
        'Bwd IAT Mean': bwd_iat_mean,
        'Bwd IAT Std': bwd_iat_std,
        'Bwd IAT Max': bwd_iat_max,
        'Bwd IAT Min': bwd_iat_min
    }

def calculate_flags_and_header_metrics(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

  
    
    
    
    # Initialize counters for flags and header lengths
    fwd_psh_flags = 0
    bwd_psh_flags = 0
    fwd_urg_flags = 0
    bwd_urg_flags = 0
    fwd_rst_flags = 0
    bwd_rst_flags = 0
    fwd_header_length = 0
    bwd_header_length = 0
    fwd_packet_count = 0
    bwd_packet_count = 0
    fwd_timestamp_start = 0
    bwd_timestamp_start = 0
    
    # Loop through the first batchsize packets
    for packet in packets[:batchsize]:
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            # Forward direction: source -> destination
            if in_subnet(ip_layer.src , source_ip) and in_subnet(ip_layer.dst , destination_ip):
                fwd_packet_count += 1
                # Count flags in forward packets
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    if tcp_layer.flags == "P":
                        fwd_psh_flags += 1
                    if tcp_layer.flags == "U":
                        fwd_urg_flags += 1
                    if tcp_layer.flags == "R":
                        fwd_rst_flags += 1
                # Add forward packet header length
                fwd_header_length += len(ip_layer) + len(packet[IP].payload)  # IP header + payload
                
                # Set start timestamp for fwd packets
                if fwd_timestamp_start is None:
                    fwd_timestamp_start = packet.time
            
            # Backward direction: destination -> source
            elif in_subnet(ip_layer.src , destination_ip) and in_subnet(ip_layer.dst , source_ip):
                bwd_packet_count += 1
                # Count flags in backward packets
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    if tcp_layer.flags == "P":
                        bwd_psh_flags += 1
                    if tcp_layer.flags == "U":
                        bwd_urg_flags += 1
                    if tcp_layer.flags == "R":
                        bwd_rst_flags += 1
                # Add backward packet header length
                bwd_header_length += len(ip_layer) + len(packet[IP].payload)  # IP header + payload
                
                # Set start timestamp for bwd packets
                if bwd_timestamp_start is None:
                    bwd_timestamp_start = packet.time

    # Calculate packets per second for fwd and bwd
    fwd_duration = packets[-1].time - fwd_timestamp_start if fwd_timestamp_start else 0
    bwd_duration = packets[-1].time - bwd_timestamp_start if bwd_timestamp_start else 0
    fwd_packets_per_second = fwd_packet_count / fwd_duration if fwd_duration > 0 else 0
    bwd_packets_per_second = bwd_packet_count / bwd_duration if bwd_duration > 0 else 0

    return {
        'Fwd PSH Flags': fwd_psh_flags,
        'Bwd PSH Flags': bwd_psh_flags,
        'Fwd URG Flags': fwd_urg_flags,
        'Bwd URG Flags': bwd_urg_flags,
        'Fwd RST Flags': fwd_rst_flags,
        'Bwd RST Flags': bwd_rst_flags,
        'Fwd Header Length': fwd_header_length,
        'Bwd Header Length': bwd_header_length,
        'Fwd Packets/s': fwd_packets_per_second,
        'Bwd Packets/s': bwd_packets_per_second
    }


def calculate_packet_length_metrics(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
   
    
    # List to store packet lengths
    packet_lengths = []

    # Collect packet lengths from the first batchsize packets
    for packet in packets[:batchsize]:
        if packet.haslayer(IP):
            # Add the length of the packet to the list
            packet_lengths.append(len(packet))
    
    # If no packets were collected
    if not packet_lengths:
        return  {
        'Packet Length Min':0,
        'Packet Length Max': 0,
        'Packet Length Mean': 0,
        'Packet Length Std': 0,
        'Packet Length Variance': 0
    }
    
    # Calculate packet length metrics
    packet_length_min = np.min(packet_lengths)
    packet_length_max = np.max(packet_lengths)
    packet_length_mean = np.mean(packet_lengths)
    packet_length_std = np.std(packet_lengths)
    packet_length_variance = np.var(packet_lengths)

    return {
        'Packet Length Min': packet_length_min,
        'Packet Length Max': packet_length_max,
        'Packet Length Mean': packet_length_mean,
        'Packet Length Std': packet_length_std,
        'Packet Length Variance': packet_length_variance
    }

def calculate_tcp_flag_counts(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    
    # Initialize flag counters
    fin_flag_count = 0
    syn_flag_count = 0
    rst_flag_count = 0
    psh_flag_count = 0
    ack_flag_count = 0
    urg_flag_count = 0
    cwr_flag_count = 0
    ece_flag_count = 0
    
    # Loop through the first batchsize packets
    for packet in packets[:batchsize]:
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            
            # Count flags in TCP packets
            if tcp_layer.flags & 0x01:  # FIN flag
                fin_flag_count += 1
            if tcp_layer.flags & 0x02:  # SYN flag
                syn_flag_count += 1
            if tcp_layer.flags & 0x04:  # RST flag
                rst_flag_count += 1
            if tcp_layer.flags & 0x08:  # PSH flag
                psh_flag_count += 1
            if tcp_layer.flags & 0x10:  # ACK flag
                ack_flag_count += 1
            if tcp_layer.flags & 0x20:  # URG flag
                urg_flag_count += 1
            if tcp_layer.flags & 0x40:  # CWR flag
                cwr_flag_count += 1
            if tcp_layer.flags & 0x80:  # ECE flag
                ece_flag_count += 1
    
    return {
        'FIN Flag Count': fin_flag_count,
        'SYN Flag Count': syn_flag_count,
        'RST Flag Count': rst_flag_count,
        'PSH Flag Count': psh_flag_count,
        'ACK Flag Count': ack_flag_count,
        'URG Flag Count': urg_flag_count,
        'CWR Flag Count': cwr_flag_count,
        'ECE Flag Count': ece_flag_count
    }

def calculate_down_up_ratio(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    
    # Initialize data counters
    downstream_data = 0
    upstream_data = 0
    
    # Loop through the first batchsize packets
    for packet in packets[:batchsize]:
        if packet.haslayer(IP):
            # Check the direction of traffic
            if packet[IP].src == packet[IP].dst:
                continue  # Skip self packets (if any)
            elif in_subnet(packet[IP].src , source_ip):  # Replace with actual source IP
                # This is upstream data (from source to destination)
                upstream_data += len(packet)
            elif in_subnet(packet[IP].dst , source_ip):  # Replace with actual source IP
                # This is downstream data (from destination to source)
                downstream_data += len(packet)
    
    # Prevent division by zero if no upstream data is found
    if upstream_data == 0:
        return 0
    
    # Calculate Down/Up Ratio
    down_up_ratio = downstream_data / upstream_data

    return down_up_ratio

def calculate_average_packet_size(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    
    # List to store packet lengths
    packet_lengths = []

    # Loop through the first batchsize packets and collect their lengths
    for packet in packets[:batchsize]:
        if packet.haslayer(IP):
            # Add the length of the packet to the list
            packet_lengths.append(len(packet))
    
    # If no valid packets are found
    if not packet_lengths:
        return 0
    
    # Calculate the average packet size
    average_packet_size = np.mean(packet_lengths)

    return average_packet_size

def calculate_fwd_bwd_segment_size_avg(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    # Initialize counters for forward and backward packets
    fwd_packet_lengths = []
    bwd_packet_lengths = []
    
    # Loop through the first batchsize packets
    for packet in packets[:batchsize]:
        if packet.haslayer(IP):
            if in_subnet(packet[IP].src , source_ip):
                # This is a forward packet (from source to destination)
                fwd_packet_lengths.append(len(packet))
            elif in_subnet(packet[IP].dst , source_ip):
                # This is a backward packet (from destination to source)
                bwd_packet_lengths.append(len(packet))
    
    # Calculate Forward Segment Size Average
    if fwd_packet_lengths:
        fwd_segment_size_avg = np.mean(fwd_packet_lengths)
    else:
        fwd_segment_size_avg = 0  # No forward packets found
    
    # Calculate Backward Segment Size Average
    if bwd_packet_lengths:
        bwd_segment_size_avg = np.mean(bwd_packet_lengths)
    else:
        bwd_segment_size_avg = 0  # No backward packets found
    
    return {
        'Fwd Segment Size Avg': fwd_segment_size_avg,
        'Bwd Segment Size Avg': bwd_segment_size_avg
    }


def calculate_fwd_bulk_metrics(pcap_file,  bulk_threshold=500):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    # Initialize counters for forward packets and bytes in bulk
    fwd_bytes = 0
    fwd_packets = 0
    bulk_fwd_bytes = 0
    bulk_fwd_packets = 0
    fwd_bulk_segments = 0
    
    total_flow_duration = 0  # This will hold the total flow duration
    
    # Loop through the first batchsize packets
    for packet in packets[:batchsize]:
        if packet.haslayer(IP):
            if in_subnet(packet[IP].src , source_ip):
                # Forward packet (from source to destination)
                fwd_bytes += len(packet)
                fwd_packets += 1
                
                # Check if the packet is part of a bulk transfer (above threshold)
                if len(packet) > bulk_threshold:
                    bulk_fwd_bytes += len(packet)
                    bulk_fwd_packets += 1
                    fwd_bulk_segments += 1  # Increment bulk segment counter
                
                # Update flow duration (time difference between first and last packet)
                if total_flow_duration == 0:
                    total_flow_duration = packet.time
                else:
                    total_flow_duration = max(total_flow_duration, packet.time)
    
    # Calculate the averages and rates
    if fwd_bulk_segments > 0:
        fwd_bytes_bulk_avg = bulk_fwd_bytes / fwd_bulk_segments
        fwd_packets_bulk_avg = bulk_fwd_packets / fwd_bulk_segments
    else:
        fwd_bytes_bulk_avg = 0
        fwd_packets_bulk_avg = 0
    
    # Calculate Forward Bulk Rate Average (bytes per second or packets per second)
    if total_flow_duration > 0:
        fwd_bulk_rate_avg_bytes = fwd_bytes / total_flow_duration
        fwd_bulk_rate_avg_packets = fwd_packets / total_flow_duration
    else:
        fwd_bulk_rate_avg_bytes = 0
        fwd_bulk_rate_avg_packets = 0
    
    return {
        'Fwd Bytes/Bulk Avg': fwd_bytes_bulk_avg,
        'Fwd Packet/Bulk Avg': fwd_packets_bulk_avg,
        'Fwd Bulk Rate Avg (Bytes/s)': fwd_bulk_rate_avg_bytes,
        'Fwd Bulk Rate Avg (Packets/s)': fwd_bulk_rate_avg_packets
    }

def calculate_bwd_bulk_metrics(pcap_file,  bulk_threshold=500):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    
    # Initialize counters for backward packets and bytes in bulk
    bwd_bytes = 0
    bwd_packets = 0
    bulk_bwd_bytes = 0
    bulk_bwd_packets = 0
    bwd_bulk_segments = 0
    
    total_flow_duration = 0  # This will hold the total flow duration
    
    # Loop through the first batchsize packets
    for packet in packets[:batchsize]:
        if packet.haslayer(IP):
            if in_subnet(packet[IP].dst , destination_ip):
                # Backward packet (from destination to source)
                bwd_bytes += len(packet)
                bwd_packets += 1
                
                # Check if the packet is part of a bulk transfer (above threshold)
                if len(packet) > bulk_threshold:
                    bulk_bwd_bytes += len(packet)
                    bulk_bwd_packets += 1
                    bwd_bulk_segments += 1  # Increment bulk segment counter
                
                # Update flow duration (time difference between first and last packet)
                if total_flow_duration == 0:
                    total_flow_duration = packet.time
                else:
                    total_flow_duration = max(total_flow_duration, packet.time)
    
    # Calculate the averages and rates
    if bwd_bulk_segments > 0:
        bwd_bytes_bulk_avg = bulk_bwd_bytes / bwd_bulk_segments
        bwd_packets_bulk_avg = bulk_bwd_packets / bwd_bulk_segments
    else:
        bwd_bytes_bulk_avg = 0
        bwd_packets_bulk_avg = 0
    
    # Calculate Backward Bulk Rate Average (bytes per second or packets per second)
    if total_flow_duration > 0:
        bwd_bulk_rate_avg_bytes = bwd_bytes / total_flow_duration
        bwd_bulk_rate_avg_packets = bwd_packets / total_flow_duration
    else:
        bwd_bulk_rate_avg_bytes = 0
        bwd_bulk_rate_avg_packets = 0
    
    return {
        'Bwd Bytes/Bulk Avg': bwd_bytes_bulk_avg,
        'Bwd Packet/Bulk Avg': bwd_packets_bulk_avg,
        'Bwd Bulk Rate Avg (Bytes/s)': bwd_bulk_rate_avg_bytes,
        'Bwd Bulk Rate Avg (Packets/s)': bwd_bulk_rate_avg_packets
    }


def calculate_subflow_fwd_metrics(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    subflow_fwd_packets = 0
    subflow_fwd_bytes = 0
    
    # Loop through the first batchsize packets
    for packet in packets[:batchsize]:
        if packet.haslayer(IP):
            # Check if the packet is in the forward direction (source -> destination)
            if in_subnet(packet[IP].src , source_ip) and in_subnet(packet[IP].dst , destination_ip):
                subflow_fwd_packets += 1
                subflow_fwd_bytes += len(packet)
    
    return {
        'Subflow Fwd Packets': subflow_fwd_packets,
        'Subflow Fwd Bytes': subflow_fwd_bytes
    }

def calculate_subflow_bwd_metrics(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    subflow_bwd_packets = 0
    subflow_bwd_bytes = 0
    
    # Loop through the first batchsize packets
    for packet in packets[:batchsize]:
        if packet.haslayer(IP):
            # Check if the packet is in the backward direction (destination -> source)
            if in_subnet(packet[IP].src , destination_ip) and in_subnet(packet[IP].dst , source_ip):
                subflow_bwd_packets += 1
                subflow_bwd_bytes += len(packet)
    
    return {
        'Subflow Bwd Packets': subflow_bwd_packets,
        'Subflow Bwd Bytes': subflow_bwd_bytes
    }

def calculate_tcp_init_win_bytes(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
  
    
    fwd_init_win_bytes = None
    bwd_init_win_bytes = None
    
    # Loop through the first batchsize packets
    for packet in packets[:batchsize]:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            # Forward direction (source -> destination)
            if in_subnet(packet[IP].src , source_ip) and in_subnet(packet[IP].dst , destination_ip):
                if fwd_init_win_bytes is None:
                    fwd_init_win_bytes = packet[TCP].window  # Initial window size in forward direction
            # Backward direction (destination -> source)
            elif in_subnet(packet[IP].src , destination_ip) and in_subnet(packet[IP].dst , source_ip):
                if bwd_init_win_bytes is None:
                    bwd_init_win_bytes = packet[TCP].window  # Initial window size in backward direction
    
    return {
        'Fwd Init Win Bytes': fwd_init_win_bytes if fwd_init_win_bytes is not None else 0,
        'Bwd Init Win Bytes': bwd_init_win_bytes if bwd_init_win_bytes is not None else 0
    }

def calculate_fwd_data_packets_and_min_seg_size(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    

    
    fwd_act_data_pkts = 0
    fwd_seg_size_min = float('inf')
    
    # Loop through the first batchsize packets
    for packet in packets[:batchsize]:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            # Forward direction (source -> destination)
            if in_subnet(packet[IP].src , source_ip) and in_subnet(packet[IP].dst , destination_ip):
                # Check if the packet contains actual data (not just control flags like SYN or ACK)
                if packet[TCP].payload:
                    fwd_act_data_pkts += 1
                    fwd_seg_size_min = min(fwd_seg_size_min, len(packet[TCP].payload))
    
    # If no data packets were found, set fwd_seg_size_min to None
    if fwd_seg_size_min == float('inf'):
        fwd_seg_size_min = 0
    
    return {
        'Fwd Act Data Pkts': fwd_act_data_pkts,
        'Fwd Seg Size Min': fwd_seg_size_min
    }

def calculate_active_metrics(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    

    time_intervals = []
    
    # Loop through the first batchsize packets and capture time intervals in the active direction
    for i in range(1, len(packets)):
        packet = packets[i]
        prev_packet = packets[i-1]
        
        if packet.haslayer(IP) and packet.haslayer(TCP):
            # Forward direction (source -> destination)
            if in_subnet(packet[IP].src , source_ip) and in_subnet(packet[IP].dst , destination_ip):
                prev_timestamp = prev_packet.time
                timestamp = packet.time
                time_intervals.append(timestamp - prev_timestamp)
    
    # Calculate Active Mean, Std, Max, and Min
    if time_intervals:
        active_mean = sum(time_intervals) / len(time_intervals)
        active_std = (sum((x - active_mean) ** 2 for x in time_intervals) / len(time_intervals)) ** 0.5
        active_max = max(time_intervals)
        active_min = min(time_intervals)
    else:
        active_mean = active_std = active_max = active_min = 0
    
    return {
        'Active Mean': active_mean,
        'Active Std': active_std,
        'Active Max': active_max,
        'Active Min': active_min
    }

def calculate_idle_metrics(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
   
    
    time_intervals = []
    
    # Loop through the first batchsize packets and capture time intervals in the idle direction
    for i in range(1, len(packets)):
        packet = packets[i]
        prev_packet = packets[i-1]
        
        if packet.haslayer(IP) and packet.haslayer(TCP):
            # Idle direction (destination -> source)
            if in_subnet(packet[IP].src , destination_ip) and in_subnet(packet[IP].dst , source_ip):
                prev_timestamp = prev_packet.time
                timestamp = packet.time
                time_intervals.append(timestamp - prev_timestamp)
    
    # Calculate Idle Mean, Std, Max, and Min
    if time_intervals:
        idle_mean = sum(time_intervals) / len(time_intervals)
        idle_std = (sum((x - idle_mean) ** 2 for x in time_intervals) / len(time_intervals)) ** 0.5
        idle_max = max(time_intervals)
        idle_min = min(time_intervals)
    else:
        idle_mean = idle_std = idle_max = idle_min = 0
    
    return {
        'Idle Mean': idle_mean,
        'Idle Std': idle_std,
        'Idle Max': idle_max,
        'Idle Min': idle_min
    }

def extract_icmp_type_code(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    icmp_info = []
    
    # Loop through packets to find ICMP packets
    for packet in packets:
        if packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            icmp_info.append({
                'ICMP Type': icmp_type,
                'ICMP Code': icmp_code
            })
    ma = 0
    for i in icmp_info:
        ma = ma + 1
    if ma == 0:
        return [0,0]
    return list(icmp_info[0].values())

def calculate_total_tcp_flow_time(pcap_file):
    packets = pcap_file
    global source_ip
    global destination_ip
    global batchsize

    
    # List to store the timestamps of TCP packets in the flow
    flow_timestamps = []
    
    # Loop through the packets and extract the TCP packets belonging to the given flow
    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(IP):
            # Check if the packet belongs to the specified source and destination IPs
            if (in_subnet(packet[IP].src , source_ip) and in_subnet(packet[IP].dst , destination_ip)) or \
               (in_subnet(packet[IP].src , destination_ip) and in_subnet(packet[IP].dst , source_ip)):
                # Append the timestamp of the packet to the list
                flow_timestamps.append(packet.time)
    
    # Ensure the flow contains at least one packet
    if flow_timestamps:
        # Total TCP Flow Time is the difference between the last and first timestamp
        total_tcp_flow_time = flow_timestamps[-1] - flow_timestamps[0]
    else:
        total_tcp_flow_time = 0
    
    return total_tcp_flow_time

def process_packet_batch(packet_batch):
    scaler = StandardScaler()
    l = []
    l.append(calculate_protocol(packet_batch))
    l.append(calculate_flow_duration(packet_batch))
    l.append(calculate_total_fwd_packets(packet_batch))
    l.append(calculate_total_bwd_packets(packet_batch))
    l.append(calculate_total_length_fwd_packets(packet_batch))
    l.append(calculate_total_length_bwd_packets(packet_batch))
    aux = calculate_fwd_packet_length_metrics(packet_batch)
    aux = list(aux.values())
    l.append(aux[0])
    l.append(aux[1])
    l.append(aux[2])
    l.append(aux[3])
    aux = calculate_bwd_packet_length_metrics(packet_batch)
    aux = list(aux.values())
    l.append(aux[0])
    l.append(aux[1])
    l.append(aux[2])
    l.append(aux[3])
    aux = calculate_flow_bytes_per_second(packet_batch)
    l.append(aux)
    aux = calculate_flow_packets_per_second(packet_batch)
    l.append(aux)
    aux = calculate_flow_iat_metrics(packet_batch)
    aux = list(aux.values())
    l.append(aux[0])
    l.append(aux[1])
    l.append(aux[2])
    l.append(aux[3])
    aux = calculate_fwd_iat_metrics(packet_batch)
    aux = list(aux.values())
    l.append(aux[0])
    l.append(aux[1])
    l.append(aux[2])
    l.append(aux[3])
    l.append(aux[4])
    aux = calculate_bwd_iat_metrics(packet_batch)
    aux = list(aux.values())
    l.append(aux[0])
    l.append(aux[1])
    l.append(aux[2])
    l.append(aux[3])
    l.append(aux[4])
    aux = calculate_flags_and_header_metrics(packet_batch)
    aux = list(aux.values())
    l.append(aux[0])
    l.append(aux[1])
    l.append(aux[2])
    l.append(aux[3])
    l.append(aux[4])
    l.append(aux[5])
    l.append(aux[6])
    l.append(aux[7])
    l.append(aux[8])
    l.append(aux[9])
    aux = calculate_packet_length_metrics(packet_batch)
    aux = list(aux.values())
    l.append(aux[0])
    l.append(aux[1])
    l.append(aux[2])
    l.append(aux[3])
    l.append(aux[4])
    aux = calculate_tcp_flag_counts(packet_batch)
    aux = list(aux.values())
    l.append(aux[0])
    l.append(aux[1])
    l.append(aux[2])
    l.append(aux[3])
    l.append(aux[4])
    l.append(aux[5])
    l.append(aux[6])
    l.append(aux[7])
    aux = calculate_down_up_ratio(packet_batch)
    l.append(aux)
    aux = calculate_average_packet_size(packet_batch)
    l.append(aux)
    aux = calculate_fwd_bwd_segment_size_avg(packet_batch)
    aux = list(aux.values())
    l.append(aux[0])
    l.append(aux[1])
    aux = calculate_fwd_bulk_metrics(packet_batch)
    aux = list(aux.values())
    l.append(aux[0])
    l.append(aux[1])
    l.append(aux[2])
    aux = calculate_bwd_bulk_metrics(packet_batch)
    aux = list(aux.values())
    l.append(aux[0])
    l.append(aux[1])
    l.append(aux[2])
    aux = calculate_subflow_fwd_metrics(packet_batch)
    aux = list(aux.values())
    l.append(aux[0])
    l.append(aux[1])
    aux = calculate_subflow_bwd_metrics(packet_batch)
    aux = list(aux.values())
    l.append(aux[0])
    l.append(aux[1])
    aux = calculate_tcp_init_win_bytes(packet_batch)
    aux = list(aux.values())
    l.append(aux[0])
    l.append(aux[1])
    aux = calculate_fwd_data_packets_and_min_seg_size(packet_batch)
    aux = list(aux.values())
    l.append(aux[0])
    l.append(aux[1])
    aux = calculate_active_metrics(packet_batch)
    aux = list(aux.values())
    l.append(aux[0])
    l.append(aux[1])
    l.append(aux[2])
    l.append(aux[3])
    aux = calculate_idle_metrics(packet_batch)
    aux = list(aux.values())
    l.append(aux[0])
    l.append(aux[1])
    l.append(aux[2])
    l.append(aux[3])
    aux = extract_icmp_type_code(packet_batch)  
    l.append(aux[1])
    l.append(aux[0])
    aux = calculate_total_tcp_flow_time(packet_batch)
    l.append(aux)
    l[0] = int(l[0])
    l[1] = int(l[1])
    l[2] = int(l[2])
    l[3] = int(l[3])
    l[4] = int(l[4])
    l[5] = int(l[5])
    l[6] = int(l[6])
    l[7] = int(l[7])
    l[8] = float(l[8])
    l[9] = float(l[9])
    l[10] = int(l[10])
    l[11] = int(l[11])
    l[12] = float(l[12])
    l[13] = float(l[13])
    l[14] = float(l[14])
    l[15] = float(l[15])
    l[16] = float(l[16])
    l[17] = float(l[17])
    l[18] = int(l[18])
    l[19] = int(l[19])
    l[20] = int(l[20])
    l[21] = float(l[21])
    l[22] = float(l[22])
    l[23] = int(l[23])
    l[24] = int(l[24])
    l[25] = int(l[25])
    l[26] = float(l[26])
    l[27] = float(l[27])
    l[28] = int(l[28])
    l[29] = int(l[29])
    l[30] = int(l[30])
    l[31] = int(l[31])
    l[32] = int(l[32])
    l[33] = int(l[33])
    l[34] = int(l[34])
    l[35] = int(l[35])
    l[36] = int(l[36])
    l[37] = int(l[37])
    l[38] = float(l[38])
    l[39] = float(l[39])
    l[40] = int(l[40])
    l[41] = int(l[41])
    l[42] = float(l[42])
    l[43] = float(l[43])
    l[44] = float(l[44])
    l[45] = int(l[45]) 
    l[46] = int(l[46]) 
    l[47] = int(l[47]) 
    l[48] = int(l[48]) 
    l[49] = int(l[49]) 
    l[50] = int(l[50]) 
    l[51] = int(l[51]) 
    l[52] = int(l[52]) 
    l[53] = float(l[53]) 
    l[54] = float(l[54]) 
    l[55] = float(l[55]) 
    l[56] = float(l[56]) 
    l[57] = int(l[57]) 
    l[58] = int(l[58]) 
    l[59] = int(l[59]) 
    l[60] = int(l[60]) 
    l[61] = int(l[61]) 
    l[62] = int(l[62]) 
    l[63] = int(l[63]) 
    l[batchsize] = int(l[batchsize]) 
    l[65] = int(l[65]) 
    l[66] = int(l[66]) 
    l[67] = int(l[67]) 
    l[68] = int(l[68]) 
    l[69] = int(l[69]) 
    l[70] = int(l[70]) 
    l[71] = float(l[71]) 
    l[72] = float(l[72]) 
    l[73] = int(l[73]) 
    l[74] = int(l[74]) 
    l[75] = float(l[75]) 
    l[76] = float(l[76]) 
    l[77] = int(l[77]) 
    l[78] = int(l[78]) 
    l[79] = int(l[79]) 
    l[80] = int(l[80]) 
    l[81] = int(l[81]) 
    return l

from sklearn.preprocessing import StandardScaler
import ipaddress
import tensorflow as tf
import numpy as np
import pandas
from scapy.all import sniff, IP, TCP, UDP
import os
import logging


if __name__ == "__main__":
    logging.basicConfig(
        filename="sniffer.log",  
        level = logging.INFO,  
        format="%(asctime)s - %(levelname)s - %(message)s"
    )


    def process_batch(packet_buffer):
        l = process_packet_batch(packet_buffer)
        pr = predict(l)
        if pr == 1:
            logging.info("Anomaly detected")
        else:
            logging.info("No anomaly detected")











    """src = ipaddress.ip_network(input("Enter the Subnet source: "))
    dst = ipaddress.ip_network(input("Enter the Subnet destination: "))
    set_source_ip(src)
    set_destination_ip(dst)
    """

    model = tf.keras.models.load_model("CICIDS_2017.keras")


    def predict(flux_packet):
        if  model.predict(flux_packet) > 0.5 : return 1 
        else: return 0



    packet_buffer = []  
    BATCH_SIZE = 64
    logging.info(f"Batch size: {BATCH_SIZE}")
    set_batchsize(BATCH_SIZE)

    def packet_callback(packet):
        global packet_buffer
        packet_buffer.append(packet)  


        if len(packet_buffer) >= BATCH_SIZE:
            process_batch(packet_buffer)  
            packet_buffer = []  


    logging.info(f"Sniffing all packets... (Processing in batches of {BATCH_SIZE})")
    try:
        sniff(prn=packet_callback)
    except KeyboardInterrupt:
        logging.info("Sniffer stopped by user")
        pass
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        pass

