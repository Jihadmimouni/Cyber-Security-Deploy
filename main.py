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
            # Code to send alert to
            #TODO: Implement alerting mechanism
            alert()
            


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

def alert():
    # Code to send alert to administrator via email 
    # Email credentials
    sender_email = "your_email@gmail.com"  # Replace with your email
    receiver_email = "nijjgrdqfzzewqlhkv@ytnhy.com"  # Replace with the recipient's email
    password = ""  # Replace with your email password

    # Create the email content
    subject = "Test Email from Python"
    body = "This is a test email sent from Python."

    # Create a MIME multipart message
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject

    # Attach the email body
    message.attach(MIMEText(body, "plain"))

    # Sending the email
    try:
        # Connect to the SMTP server
        with smtplib.SMTP("smtp.gmail.com", 587) as server:  # Replace with your email provider's SMTP server and port
            server.starttls()  # Upgrade the connection to a secure encrypted SSL/TLS connection
            server.login(sender_email, password)  # Log in to the email account
            server.sendmail(sender_email, receiver_email, message.as_string())  # Send the email
            logging.info(f"Email sent: {subject}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")


# Sniff packets
logging.info(f"Sniffing all packets... (Processing in batches of {BATCH_SIZE})")
try:
    sniff(iface=interface,prn=packet_callback)
except Exception as e:
    logging.error(f"An error occurred during packet sniffing: {e}")
    pass
