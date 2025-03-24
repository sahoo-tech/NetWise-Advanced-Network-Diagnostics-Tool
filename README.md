# Advanced Network Diagnostics Tool

A comprehensive network diagnostics tool for Linux that provides advanced network analysis, monitoring, and troubleshooting capabilities.

## Table of Contents
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Options](#options)
- [Examples](#examples)
- [Data Structure](#data-structure)
- [Advanced Features](#advanced-features)
- [Security Note](#security-note)
- [Contributing](#contributing)
- [License](#license)

## Features

### Basic Diagnostics
- Advanced ping testing with detailed statistics
- Multi-type port scanning (SYN, UDP, Connect, FIN, XMAS, NULL)
- Comprehensive DNS resolution with multiple record types
- Network speed testing with server selection
- Traceroute analysis
- Advanced SSL certificate checking

### Advanced Features
- Network interface monitoring and statistics
- Real-time packet analysis and sniffing
- WHOIS information lookup
- Detailed network interface information
- Colored output for better readability
- Report generation and export
- Concurrent operations support
- Detailed logging

## Prerequisites

- Python 3.6 or higher
- Linux operating system
- Root privileges for some operations (like port scanning and packet sniffing)
- Required system packages:
  ```bash
  sudo apt-get install python3-scapy
  sudo apt-get install traceroute
  ```

## Installation

1. Clone this repository or download the files:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

The tool can be used with various command-line arguments:

```bash
python network_diagnostics.py [options]
```

### Options

- `--host <hostname>`: Target host to diagnose (e.g., example.com or 192.168.1.1)
- `--domain <domain>`: Domain for DNS lookup and SSL certificate check
- `--interface <interface>`: Network interface to monitor (e.g., eth0, wlan0)
- `--speed`: Run network speed test
- `--scan-type <type>`: Port scan type (SYN, UDP, Connect, FIN, XMAS, NULL)
- `--duration <seconds>`: Duration for interface monitoring (default: 10)
- `--all`: Run all available diagnostics
- `--output <file>`: Save the report to a file

### Examples

1. Run all diagnostics on a specific host with custom scan type:
   ```bash
   python network_diagnostics.py --host example.com --scan-type SYN,UDP --all
   ```

2. Monitor network interface and analyze packets:
   ```bash
   python network_diagnostics.py --interface eth0 --duration 30
   ```

3. Check domain information and SSL certificate:
   ```bash
   python network_diagnostics.py --domain example.com --output report.txt
   ```

4. Run speed test and save results:
   ```bash
   python network_diagnostics.py --speed --output speed_report.txt
   ```

## Data Structure

## Advanced Features

### Network Interface Monitoring
- Real-time monitoring of network interface statistics
- Packet counts and byte statistics
- Interface status and MTU information

### Packet Analysis
- Capture and analyze network packets
- Source and destination IP tracking
- Protocol analysis
- Packet size statistics

### Advanced Port Scanning
- Multiple scan types support
- Comprehensive port range scanning
- Service detection
- OS fingerprinting

### SSL Certificate Analysis
- Detailed certificate information
- Expiration date checking
- Issuer and subject information
- Certificate extensions analysis

## Security Note

Some features of this tool (like port scanning and packet sniffing) require root privileges and should be used responsibly and only on networks you have permission to test. Always ensure you have proper authorization before performing network diagnostics.

## Contributing

Contributions are welcome! If you would like to contribute to this project, please follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your changes to your forked repository.
5. Submit a pull request detailing your changes.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

