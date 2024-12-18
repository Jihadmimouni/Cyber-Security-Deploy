# Network Intrusion Detection System (NIDS)

This repository contains a Network Intrusion Detection System (NIDS) trained on the CICIDS 2017 dataset. The NIDS utilizes machine learning and deep learning techniques to monitor and identify anomalous network activity in real-time.

## Features
- **Real-time Packet Capture:** Sniffs and processes network packets in real-time.
- **Anomaly Detection:** Predicts network anomalies using a pre-trained TensorFlow deep learning model.
- **Batch Processing:** Processes packets in batches for efficient computation.
- **Logging:** Logs detected anomalies and errors to a log file.

## Dataset
The model is trained using the [CICIDS 2017 dataset](https://www.unb.ca/cic/datasets/ids-2017.html), which provides labeled data for intrusion detection.

## Installation
### Prerequisites
- Python 3.8+
- TensorFlow
- NumPy
- Pandas
- scikit-learn
- Scapy
- flux (custom module for packet processing)
- ipaddress
- Logging module (built-in Python library)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/Jihadmimouni/Cyber-Security-Deploy
   cd Cyber-Security-Deploy
   ```

2. Install the required Python libraries:
   ```bash
   pip install -r requirements.txt
   ```

3. Place the pre-trained TensorFlow model file (`CICIDS_2017.keras`) in the root directory of the repository.

## Usage
1. Update the source and destination subnets if needed (commented code provided in `main.py`).
   ```python
   src = ipaddress.ip_network("192.168.1.0/24")
   dst = ipaddress.ip_network("10.0.0.0/24")
   fl.set_source_ip(src)
   fl.set_destination_ip(dst)
   ```

2. Start the packet sniffer:
   ```bash
   python main.py
   ```

3. The system will:
   - Capture packets in real-time.
   - Process them in batches (default batch size: 64).
   - Predict whether each batch contains anomalous traffic.
   - Log detected anomalies to `sniffer.log`.

## File Structure
- `main.py`: Main script for the NIDS.
- `CICIDS_2017.keras`: Pre-trained TensorFlow model.
- `requirements.txt`: List of required Python libraries.
- `sniffer.log`: Log file for detected anomalies and errors.

## Model Description
The deep learning model is trained on extracted features from the CICIDS 2017 dataset. The features are scaled using `StandardScaler` from `scikit-learn` before training. The model outputs a binary prediction:
- **1:** Anomalous traffic detected.
- **0:** Normal traffic.

### Prediction Function
```python
def predict(flux_packet):
    flux_packet = np.array(flux_packet).reshape(1, -1)
    pl = model.predict(flux_packet)
    return 1 if pl[0][0] > 0.5 else 0
```

## Logging
The system logs messages and detected anomalies to `sniffer.log` in the following format:
```plaintext
YYYY-MM-DD HH:MM:SS - INFO - Anomaly detected
YYYY-MM-DD HH:MM:SS - ERROR - An error occurred: <error_message>
```

## Notes
- Ensure that the required permissions are granted to capture network packets (run as administrator or with `sudo` if necessary).
- Use in a controlled environment to avoid unauthorized monitoring of network traffic.
- Batch size for packet processing can be adjusted using the `BATCH_SIZE` variable in the script.

## Contributing
Contributions are welcome! Feel free to fork the repository and submit pull requests.

## Acknowledgments
- [CICIDS 2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html) for providing a comprehensive dataset for intrusion detection.
- TensorFlow and scikit-learn communities for tools and documentation.
- The developers of Scapy for enabling real-time packet sniffing and analysis.

