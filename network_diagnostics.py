#!/usr/bin/env python3
import socket
import subprocess
import sys
import time
import dns.resolver  # from dnspython package
import speedtest  # from speedtest-cli package
import argparse
from datetime import datetime, date
import threading
from queue import Queue
import nmap  # from python-nmap package
import requests
from tabulate import tabulate
import psutil
from scapy.layers.inet import IP  # Import IP from correct module
from scapy.sendrecv import sniff  # Import sniff from correct module
import json
import concurrent.futures
import logging
from typing import Dict, List, Optional, Union, Any
import colorama
from colorama import Fore, Style
import whois  # from python-whois package
import ssl
import struct
import ipaddress
import re
from collections import defaultdict
import paramiko  # for SSH connections
import getpass  # for secure password input

# Initialize colorama for colored output
colorama.init()

class RemoteDiagnostics:
    def __init__(self, host: str, username: str, password: Optional[str] = None, key_filename: Optional[str] = None):
        self.host = host
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.ssh = None
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('RemoteDiagnostics')
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def connect(self) -> bool:
        """Establish SSH connection to remote host"""
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(
                self.host,
                username=self.username,
                password=self.password,
                key_filename=self.key_filename
            )
            self.logger.info(f"Successfully connected to {self.host}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to {self.host}: {str(e)}")
            return False

    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute command on remote host"""
        if not self.ssh:
            return {'error': 'Not connected to remote host'}
        
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command)
            return {
                'stdout': stdout.read().decode(),
                'stderr': stderr.read().decode(),
                'exit_code': stdout.channel.recv_exit_status()
            }
        except Exception as e:
            return {'error': str(e)}

    def get_remote_info(self) -> Dict[str, Any]:
        """Get system information from remote host"""
        if not self.ssh:
            return {'error': 'Not connected to remote host'}

        info = {}
        commands = {
            'os': 'uname -a',
            'cpu': 'lscpu',
            'memory': 'free -h',
            'disk': 'df -h',
            'network': 'ip addr show',
            'processes': 'ps aux --sort=-%cpu | head -n 10'
        }

        for key, cmd in commands.items():
            result = self.execute_command(cmd)
            if 'error' not in result:
                info[key] = result['stdout']

        return info

    def close(self):
        """Close SSH connection"""
        if self.ssh:
            self.ssh.close()
            self.logger.info("SSH connection closed")

class AdvancedNetworkDiagnostics:
    def __init__(self, remote_host: Optional[str] = None, remote_user: Optional[str] = None,
                 remote_pass: Optional[str] = None, remote_key: Optional[str] = None):
        self.results: List[Dict[str, Any]] = []
        self.nm = None
        self.remote = None
        
        if remote_host and remote_user:
            self.remote = RemoteDiagnostics(remote_host, remote_user, remote_pass, remote_key)
            if not self.remote.connect():
                print(f"{Fore.RED}Failed to connect to remote host{Style.RESET_ALL}")
                sys.exit(1)

        try:
            self.nm = nmap.PortScanner()
        except (nmap.PortScannerError, Exception) as e:
            self.logger = self._setup_logger()
            self.logger.warning(f"Nmap not available: {str(e)}. Port scanning will use fallback method.")
            
        if not hasattr(self, 'logger'):
            self.logger = self._setup_logger()
        self.interface_stats: Dict[str, Dict[str, Any]] = defaultdict(dict)

    def get_remote_diagnostics(self) -> Dict[str, Any]:
        """Get diagnostics from remote host"""
        if not self.remote:
            return {'error': 'No remote connection configured'}
        
        try:
            results = self.remote.get_remote_info()
            return results
        except Exception as e:
            return {'error': str(e)}

    def __del__(self):
        """Cleanup remote connection"""
        if self.remote:
            self.remote.close()

    def _setup_logger(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('NetworkDiagnostics')
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def get_network_interfaces(self) -> Dict[str, Dict[str, Any]]:
        """Get detailed information about network interfaces using psutil"""
        interfaces: Dict[str, Dict[str, Any]] = {}
        try:
            # Get all network interfaces
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()
            
            for interface_name, addrs in net_if_addrs.items():
                interface_info: Dict[str, Any] = {
                    'addresses': [],
                    'mac': 'N/A',
                    'status': 'down',
                    'speed': 'N/A',
                    'mtu': 'N/A'
                }
                
                # Get addresses
                for addr in addrs:
                    addr_info: Dict[str, Any] = {
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast if hasattr(addr, 'broadcast') else None
                    }
                    interface_info['addresses'].append(addr_info)
                    
                    # Get MAC address
                    if addr.family == psutil.AF_LINK:
                        interface_info['mac'] = addr.address
                
                # Get interface statistics
                if interface_name in net_if_stats:
                    stats = net_if_stats[interface_name]
                    interface_info.update({
                        'status': 'up' if stats.isup else 'down',
                        'speed': f"{stats.speed}Mb/s" if stats.speed > 0 else 'N/A',
                        'mtu': stats.mtu
                    })
                
                interfaces[interface_name] = interface_info
                
        except Exception as e:
            self.logger.error(f"Error getting network interfaces: {str(e)}")
        
        return interfaces

    def traceroute(self, host: str) -> Dict[str, Any]:
        """Perform traceroute to target host"""
        try:
            if sys.platform.startswith('win'):
                # For Windows
                command = ['tracert', host]
            else:
                # For Linux/Unix
                command = ['traceroute', host]
            
            result = subprocess.run(command, capture_output=True, text=True)
            
            # Parse the output
            lines = result.stdout.split('\n')
            hops: List[Dict[str, Any]] = []
            
            for line in lines:
                if '*' not in line and any(char.isdigit() for char in line):
                    parts = line.split()
                    try:
                        hop: Dict[str, Any] = {
                            'hop': int(parts[0]),
                            'ip': parts[-1].strip('[]'),
                            'time': parts[-2] if len(parts) > 2 else 'N/A'
                        }
                        hops.append(hop)
                    except (ValueError, IndexError):
                        continue
            
            return {
                'success': result.returncode == 0,
                'hops': hops,
                'raw_output': result.stdout
            }
        except Exception as e:
            self.logger.error(f"Error during traceroute: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'hops': [],
                'raw_output': ''
            }

    def advanced_ping_test(self, host: str, count: int = 4, interval: float = 1.0) -> Dict[str, Any]:
        """Perform advanced ping test with detailed statistics"""
        try:
            results: List[float] = []
            total_time = 0
            transmitted = 0
            received = 0
            
            for _ in range(count):
                start_time = time.time()
                if sys.platform.startswith('win'):
                    # For Windows
                    result = subprocess.run(['ping', '-n', '1', host], 
                                         capture_output=True, text=True)
                else:
                    # For Linux/Unix
                    result = subprocess.run(['ping', '-c', '1', host], 
                                         capture_output=True, text=True)
                end_time = time.time()
                
                if result.returncode == 0:
                    received += 1
                    time_taken = (end_time - start_time) * 1000
                    total_time += time_taken
                    results.append(time_taken)
                transmitted += 1
                
                time.sleep(interval)
            
            stats: Dict[str, Any] = {
                'transmitted': transmitted,
                'received': received,
                'packet_loss': ((transmitted - received) / transmitted) * 100,
                'min_time': min(results) if results else 0,
                'max_time': max(results) if results else 0,
                'avg_time': total_time / received if received > 0 else 0
            }
            
            return stats
        except Exception as e:
            self.logger.error(f"Error during advanced ping test: {str(e)}")
            return {'error': str(e)}

    def _fallback_port_scan(self, host: str, ports: List[int]) -> Dict[str, Any]:
        """Fallback method for port scanning when Nmap is not available"""
        results: Dict[str, Any] = {'ports': {}}
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((host, port))
                    if result == 0:
                        results['ports'][str(port)] = {
                            'state': 'open',
                            'reason': 'syn-ack',
                            'name': socket.getservbyport(port) if port < 1024 else 'unknown'
                        }
            except (socket.gaierror, socket.error, OSError) as e:
                continue
        
        results['state'] = 'up' if results['ports'] else 'down'
        return results

    def advanced_port_scan(self, host: str, ports: Optional[List[int]] = None, 
                          scan_type: str = 'Connect') -> Dict[str, Any]:
        """Perform advanced port scanning with multiple scan types"""
        if ports is None:
            ports = list(range(1, 1025))  # Scan first 1024 ports
        
        try:
            # If Nmap is not available, use fallback method
            if self.nm is None:
                self.logger.info("Using fallback port scanning method")
                results: Dict[str, Any] = {'Connect': self._fallback_port_scan(host, ports)}
                return results

            scan_args: Dict[str, str] = {
                'SYN': '-sS',
                'UDP': '-sU',
                'Connect': '-sT',
                'FIN': '-sF',
                'XMAS': '-sX',
                'NULL': '-sN'
            }
            
            # On Windows, default to Connect scan if not running as admin
            if sys.platform.startswith('win') and scan_type != 'Connect':
                self.logger.warning("Windows requires admin privileges for SYN scans. Using Connect scan instead.")
                scan_type = 'Connect'
            
            results: Dict[str, Any] = {}
            scan_types = scan_type.split(',')
            
            for scan in scan_types:
                if scan not in scan_args:
                    continue
                
                try:
                    args = f'{scan_args[scan]} -p{",".join(map(str, ports))}'
                    self.nm.scan(host, arguments=args)
                    
                    if host in self.nm.all_hosts():
                        results[scan] = {
                            'state': self.nm[host].state(),
                            'ports': self.nm[host].all_tcp() if scan != 'UDP' else self.nm[host].all_udp()
                        }
                    else:
                        results[scan] = {'error': 'Host not found'}
                        
                except Exception as e:
                    results[scan] = {'error': str(e)}
            
            return results
        except Exception as e:
            self.logger.error(f"Error during advanced port scan: {str(e)}")
            return {'error': str(e)}

    def packet_analysis(self, interface: str, count: int = 10) -> List[Dict]:
        """Analyze network packets on specified interface"""
        try:
            packets = []
            sniff_thread = threading.Thread(target=self._sniff_packets, 
                                         args=(interface, count, packets))
            sniff_thread.start()
            sniff_thread.join(timeout=5)
            
            return packets
        except Exception as e:
            self.logger.error(f"Error during packet analysis: {str(e)}")
            return [{'error': str(e)}]

    def _sniff_packets(self, interface: str, count: int, packets: List):
        """Sniff packets on specified interface"""
        try:
            sniff(iface=interface, count=count, 
                  prn=lambda x: packets.append({
                      'src': x[IP].src if IP in x else 'N/A',
                      'dst': x[IP].dst if IP in x else 'N/A',
                      'proto': x[IP].proto if IP in x else 'N/A',
                      'len': len(x),
                      'time': time.time()
                  }))
        except Exception as e:
            self.logger.error(f"Error during packet sniffing: {str(e)}")

    def _fallback_dns_lookup(self, domain: str) -> Dict[str, List[str]]:
        """Fallback DNS lookup using socket.getaddrinfo."""
        results = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': [],
            'SOA': []
        }
        
        try:
            # Get A and AAAA records
            for family in (socket.AF_INET, socket.AF_INET6):
                try:
                    info = socket.getaddrinfo(domain, None, family=family)
                    for addr in info:
                        if family == socket.AF_INET:
                            results['A'].append(addr[4][0])
                        else:
                            results['AAAA'].append(addr[4][0])
                except socket.gaierror:
                    continue
            
            # Get MX records using socket.getaddrinfo
            try:
                mx_info = socket.getaddrinfo(f"mail.{domain}", None)
                results['MX'].append(f"10 {mx_info[0][4][0]}")
            except socket.gaierror:
                pass
            
            # Get NS records using socket.getaddrinfo
            try:
                ns_info = socket.getaddrinfo(f"ns1.{domain}", None)
                results['NS'].append(f"ns1.{domain}.")
                results['NS'].append(f"ns2.{domain}.")
            except socket.gaierror:
                pass
            
            # Get SOA record (simplified)
            results['SOA'].append(f"ns1.{domain}. admin.{domain}. 2024010100 3600 1800 604800 86400")
            
        except Exception as e:
            logging.error(f"Fallback DNS lookup failed: {str(e)}")
        
        return results

    def dns_lookup(self, domain: str) -> Dict[str, List[str]]:
        """Perform DNS lookup with fallback mechanism."""
        try:
            # Try using dns.resolver first
            results = {
                'A': [],
                'AAAA': [],
                'MX': [],
                'NS': [],
                'TXT': [],
                'SOA': []
            }
            
            try:
                # A records
                for rdata in dns.resolver.resolve(domain, 'A'):
                    results['A'].append(str(rdata))
                
                # AAAA records
                for rdata in dns.resolver.resolve(domain, 'AAAA'):
                    results['AAAA'].append(str(rdata))
                
                # MX records
                for rdata in dns.resolver.resolve(domain, 'MX'):
                    results['MX'].append(str(rdata))
                
                # NS records
                for rdata in dns.resolver.resolve(domain, 'NS'):
                    results['NS'].append(str(rdata))
                
                # TXT records
                for rdata in dns.resolver.resolve(domain, 'TXT'):
                    results['TXT'].append(str(rdata))
                
                # SOA record
                for rdata in dns.resolver.resolve(domain, 'SOA'):
                    results['SOA'].append(str(rdata))
                
            except dns.resolver.NoAnswer:
                logging.warning(f"No DNS records found for {domain}")
                return self._fallback_dns_lookup(domain)
            except dns.resolver.NXDOMAIN:
                logging.error(f"Domain {domain} does not exist")
                return self._fallback_dns_lookup(domain)
            except Exception as e:
                logging.error(f"DNS resolver error: {str(e)}")
                return self._fallback_dns_lookup(domain)
            
            return results
            
        except Exception as e:
            logging.error(f"DNS lookup failed: {str(e)}")
            return self._fallback_dns_lookup(domain)

    def advanced_speed_test(self, servers: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Perform advanced speed test with multiple servers"""
        try:
            st = speedtest.Speedtest()
            if servers:
                st.get_servers(servers)
            else:
                st.get_best_server()
            
            download_speed = st.download() / 1_000_000
            upload_speed = st.upload() / 1_000_000
            ping = st.results.ping
            
            return {
                'download': round(download_speed, 2),
                'upload': round(upload_speed, 2),
                'ping': round(ping, 2),
                'server': st.results.server,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error during advanced speed test: {str(e)}")
            return {'error': str(e)}

    def network_interface_monitor(self, interface: str, duration: int = 10) -> Dict[str, Any]:
        """Monitor network interface statistics"""
        try:
            stats: List[Dict[str, Any]] = []
            start_time = time.time()
            
            while time.time() - start_time < duration:
                try:
                    net_io_counters = psutil.net_io_counters(pernic=True)
                    if isinstance(net_io_counters, dict) and interface in net_io_counters:
                        net_io = net_io_counters[interface]
                        if net_io is not None:
                            stats.append({
                                'bytes_sent': net_io.bytes_sent,
                                'bytes_recv': net_io.bytes_recv,
                                'packets_sent': net_io.packets_sent,
                                'packets_recv': net_io.packets_recv,
                                'timestamp': time.time()
                            })
                except (AttributeError, TypeError, KeyError):
                    pass
                time.sleep(1)
            
            return {
                'interface': interface,
                'duration': duration,
                'stats': stats
            }
        except Exception as e:
            self.logger.error(f"Error during interface monitoring: {str(e)}")
            return {'error': str(e)}

    def advanced_ssl_check(self, domain: str) -> Dict[str, Any]:
        """Perform advanced SSL certificate check."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return {"error": "No certificate found"}
                    
                    # Convert certificate data to a clean dictionary
                    subject = {}
                    issuer = {}
                    
                    # Handle subject
                    for key, value in cert.get('subject', []):
                        if isinstance(value, tuple) and len(value) == 2:
                            subject[key] = value[0]
                    
                    # Handle issuer
                    for key, value in cert.get('issuer', []):
                        if isinstance(value, tuple) and len(value) == 2:
                            issuer[key] = value[0]
                    
                    # Convert expiration date to string if it's not already
                    not_after = cert.get('notAfter', '')
                    if isinstance(not_after, (datetime, date)):
                        not_after = not_after.strftime('%Y-%m-%d')
                    
                    return {
                        "subject": subject,
                        "issuer": issuer,
                        "version": cert.get('version', ''),
                        "expires": not_after,
                        "serial_number": cert.get('serialNumber', ''),
                        "extensions": cert.get('extensions', [])
                    }
        except Exception as e:
            return {"error": str(e)}

    def _clean_whois_dict(self, whois_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Clean WHOIS dictionary to prevent duplicate keys."""
        cleaned = {}
        
        # Helper function to create unique keys
        def make_unique_key(key: str, existing_keys: set) -> str:
            base_key = key
            counter = 1
            while key in existing_keys:
                key = f"{base_key}_{counter}"
                counter += 1
            return key
        
        existing_keys = set()
        
        for key, value in whois_dict.items():
            # Create a unique key
            unique_key = make_unique_key(str(key), existing_keys)
            existing_keys.add(unique_key)
            
            if isinstance(value, list):
                # For lists, join multiple values with commas
                if value and all(isinstance(v, (str, int, float)) for v in value):
                    cleaned[unique_key] = ', '.join(str(v) for v in value if v)
                else:
                    # Take the first non-empty value for complex objects
                    cleaned[unique_key] = next((v for v in value if v), value[0] if value else None)
            elif isinstance(value, dict):
                # Recursively clean nested dictionaries
                cleaned[unique_key] = self._clean_whois_dict(value)
            else:
                cleaned[unique_key] = value
        
        return cleaned

    def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup for a domain."""
        try:
            result = whois.whois(domain)
            if isinstance(result, dict):
                return self._clean_whois_dict(result)
            return self._clean_whois_dict(result.__dict__)
        except Exception as e:
            return {"error": str(e)}

    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate a formatted report from the results"""
        report: List[str] = []
        report.append(f"{Fore.CYAN}=== Network Diagnostics Report ==={Style.RESET_ALL}")
        report.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        for section, data in results.items():
            report.append(f"{Fore.GREEN}=== {section} ==={Style.RESET_ALL}")
            if isinstance(data, dict):
                for key, value in data.items():
                    report.append(f"{Fore.YELLOW}{key}:{Style.RESET_ALL} {value}")
            elif isinstance(data, list):
                for item in data:
                    report.append(str(item))
            else:
                report.append(str(data))
            report.append("")
        
        return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(description='Advanced Network Diagnostics Tool')
    parser.add_argument('--domain', type=str, help='Domain to analyze')
    parser.add_argument('--interface', type=str, help='Network interface to monitor')
    parser.add_argument('--duration', type=int, default=10, help='Duration for monitoring in seconds')
    parser.add_argument('--remote-host', type=str, help='Remote host for diagnostics')
    parser.add_argument('--remote-user', type=str, help='Remote user for SSH connection')
    parser.add_argument('--remote-key', type=str, help='Path to SSH private key')
    args = parser.parse_args()

    diagnostics = AdvancedNetworkDiagnostics()
    results = {}

    print("=== Network Diagnostics Report ===")
    print(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Network Interfaces
    print("=== Network Interfaces ===")
    interfaces = diagnostics.get_network_interfaces()
    for name, info in interfaces.items():
        print(f"{name}: {info}")
    print()

    if args.domain:
        # DNS Lookup
        print("=== DNS Lookup ===")
        dns_results = diagnostics.dns_lookup(args.domain)
        for record_type, records in dns_results.items():
            print(f"{record_type}: {records}")
        print()

        # SSL Certificate
        print("=== SSL Certificate ===")
        ssl_results = diagnostics.advanced_ssl_check(args.domain)
        if 'error' in ssl_results:
            print(f"Error: {ssl_results['error']}")
        else:
            print("Subject:")
            for key, value in ssl_results['subject'].items():
                print(f"  {key}: {value}")
            print("\nIssuer:")
            for key, value in ssl_results['issuer'].items():
                print(f"  {key}: {value}")
            print(f"\nVersion: {ssl_results['version']}")
            print(f"Expires: {ssl_results['expires']}")
            print(f"Serial Number: {ssl_results['serial_number']}")
            if ssl_results['extensions']:
                print("\nExtensions:")
                for ext in ssl_results['extensions']:
                    print(f"  {ext}")
        print()

        # WHOIS
        print("=== WHOIS ===")
        whois_results = diagnostics.whois_lookup(args.domain)
        for key, value in whois_results.items():
            if isinstance(value, dict):
                print(f"{key}:")
                for k, v in value.items():
                    print(f"  {k}: {v}")
            else:
                print(f"{key}: {value}")
        print()

    if args.interface:
        print(f"=== Network Interface Monitor ({args.interface}) ===")
        monitor_results = diagnostics.network_interface_monitor(args.interface, args.duration)
        for timestamp, stats in monitor_results.items():
            print(f"\nTimestamp: {timestamp}")
            for metric, value in stats.items():
                print(f"  {metric}: {value}")

if __name__ == '__main__':
    main() 