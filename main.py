import time
from sklearn.preprocessing import StandardScaler
import flux as fl
import ipaddress
import tensorflow as tf
import numpy as np
import pandas
from scapy.all import sniff, IP, TCP, UDP ,ICMP
import os
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from scapy.all import wrpcap

global sentmail 
sentmail = False
interface = r"\Device\NPF_{581C6813-F330-4245-AC76-465A5C73B185}"

# Configure logging
logging.basicConfig(
    filename="sniffer.log",  
    level=logging.INFO,  
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Function to process a batch of packets
def process_batch(packet_buffer):
    try:
        logging.info(f"Processing a batch of {len(packet_buffer)} packets.")
        l = fl.process_packet_batch(packet_buffer)  # Process packets
        logging.info(f"Batch processed. Preparing for prediction.")
        pr = predict(l)  # Perform prediction
        if pr == 0:
            print("Anomaly detected in the batch!")
            logging.warning("Anomaly detected in the batch!")
            logging.warning("Sending alert to administrator...")
            # Get the current time in a readable format (e.g., YYYY-MM-DD_HH-MM-SS)
            current_time = time.strftime("%Y-%m-%d_%H-%M-%S")

            # Save the packets to a pcap file with the current time as the filename
            wrpcap(f"{current_time}.pcap", packet_buffer)
            # Code to send alert to
            #TODO: Implement alerting mechanism
            alert(f"{current_time}.pcap")
            


        else:
            logging.info("Batch classified as normal.")

    except KeyboardInterrupt:
        logging.info("Sniffer stopped by user.")
    except Exception as e:
        logging.error(f"Error during batch processing {e}")
        pass

# Load pre-trained model
model = tf.keras.models.load_model("CICIDS_2017.keras")
logging.info("Loaded model: CICIDS_2017.keras")

# Function to predict based on processed data
def predict(flux_packet):
    try:
        flux_packet = np.array(flux_packet).reshape(1, -1)
        pl = model.predict(flux_packet)
        logging.info(f"Prediction result: {pl}")
        
        if pl[0][0] > 0.5:
            return 1
        else:
            return 0
    except Exception as e:
        logging.error(f"Error during prediction: {e}")
        return 0

# Initialize packet buffer and batch size
packet_buffer = []
BATCH_SIZE = 64
logging.info(f"Batch size set to {BATCH_SIZE}.")
fl.set_batchsize(BATCH_SIZE)

# Callback function for packet capture
def packet_callback(packet):
    global packet_buffer
    try:
        # Add packet to buffer
        packet_buffer.append(packet)
        logging.debug(f"Packet added to buffer. Buffer size: {len(packet_buffer)}")

        # Process batch if buffer size exceeds batch size
        if len(packet_buffer) >= BATCH_SIZE:
            logging.info("Batch size reached. Processing...")
            process_batch(packet_buffer)
            packet_buffer = []
    except Exception as e:
        logging.error(f"Error in packet callback: {e}")
        pass

def alert(f):
    global sentmail
    if sentmail:
        return
    sentmail = True
    # Code to send alert to administrator via email 
    # Email credentials
    sender_email = ""  # Replace with your email
    receiver_email = ""  # Replace with the recipient's email
    password = ""  # Replace with your email password
    # Create the email content
    subject = "Intrusion Alert: Suspicious Activity Detected"
    body = """
    Dear Admin,

    This is an automated alert regarding suspicious network activity detected on the system. An intrusion attempt has been identified, and the following packet capture file is attached for your review. Please investigate and take necessary action.

    Best regards,
    Your Security System
    """

    # Create a MIME multipart message
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject

    # Attach the email body
    message.attach(MIMEText(body, "plain"))

    # Attach the packet capture file (e.g., 'intrusion_packets.pcap')
    filename = f  # Replace with the actual file name
    attachment = open(filename, "rb")

    part = MIMEBase("application", "octet-stream")
    part.set_payload(attachment.read())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f"attachment; filename={filename}")

    # Attach the file to the email
    message.attach(part)

    # Sending the email
    try:
        # Connect to the SMTP server
        with smtplib.SMTP("smtp.gmail.com", 587) as server:  # Replace with your email provider's SMTP server and port
            server.starttls()  # Upgrade the connection to a secure encrypted SSL/TLS connection
            server.login(sender_email, password)  # Log in to the email account
            server.sendmail(sender_email, receiver_email, message.as_string())  # Send the email
        print("Email sent successfully.")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Sniff packets
logging.info(f"Sniffing all packets... (Processing in batches of {BATCH_SIZE})")
try:
    sniff(iface=interface,prn=packet_callback)
except Exception as e:
    logging.error(f"An error occurred during packet sniffing: {e}")
    pass
