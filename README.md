# Network Traffic Analyzer Using Wireshark

## About the Project
This is a beginner-friendly cybersecurity project that uses Wireshark to capture and analyze network traffic in a safe lab environment.

## Features
- DNS request and response analysis
- TCP three-way handshake analysis
- HTTP traffic inspection
- IP address and port identification
- Detection of potentially exposed plaintext data
- Basic Python packet analysis

## Tools & Technologies
- Wireshark
- Python
- TCP/IP
- DNS
- HTTP/HTTPS
- PCAP

## Project Structure
- `captures/` — Sample network traffic capture
- `scripts/` — Python analysis scripts
- `reports/` — Analysis report templates
- `wireshark/` — Wireshark display filters
- `README.md` — Project documentation
- `requirements.txt` — Python dependencies information

## How to Run
1. Install Wireshark from https://www.wireshark.org/download.html
2. Download or clone this repository.
3. Open `captures/sample_traffic.pcap` in Wireshark.
4. Apply display filters such as `dns`, `tcp`, and `http`.
5. Run the Python analyzer:

   `python scripts/quick_analyze.py`

## Learning Outcomes
- Understand basic network communication.
- Analyze DNS and TCP traffic.
- Identify plaintext HTTP data exposure.
- Learn fundamental network security analysis.

## Disclaimer
This project is intended for educational purposes only. The included packet capture contains synthetic training data. Analyze only network traffic that you own or have permission to inspect.

## Author
Pradnya Gaikwad
