from sklearn.preprocessing import StandardScaler
import flux as fl
import ipaddress
import tensorflow as tf
import numpy as np
import pandas
from scapy.all import sniff, IP, TCP, UDP
import os
import logging



logging.basicConfig(
    filename="sniffer.log",  
    level = logging.INFO,  
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def process_batch(packet_buffer):
    try :
        l = fl.process_packet_batch(packet_buffer)
        pr = predict(l)
        print(pr)
        if pr == 1:
            logging.info("Anomaly detected")
            
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        pass




    




"""
src = ipaddress.ip_network(input("Enter the Subnet source: "))
dst = ipaddress.ip_network(input("Enter the Subnet destination: "))
fl.set_source_ip(src)
fl.set_destination_ip(dst)

"""
model = tf.keras.models.load_model("CICIDS_2017.keras")


def predict(flux_packet):
    flux_packet = np.array(flux_packet).reshape(1, -1)
    pl = model.predict(flux_packet)
    if  pl[0][0] > 0.5 : return 1 
    else: return 0



packet_buffer = []  
BATCH_SIZE = 64
logging.info(f"Batch size: {BATCH_SIZE}")
fl.set_batchsize(BATCH_SIZE)

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

