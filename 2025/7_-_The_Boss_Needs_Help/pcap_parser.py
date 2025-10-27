#!/usr/bin/env python3
"""
PCAPNG HTTP Parser - Clean and Simple
"""

import sys
import argparse
from collections import defaultdict
from scapy.all import rdpcap, TCP, IP, Raw
import re

class TCPStream:
    def __init__(self):
        self.packets = []
        self.client_data = b""
        self.server_data = b""
    
    def add_packet(self, packet, src_ip, src_port, dst_ip, dst_port, payload, seq, ack, flags):
        is_client_to_server = (src_ip, src_port) == self.client
        
        if is_client_to_server:
            self.client_data += payload
        else:
            self.server_data += payload
        
        self.packets.append({
            'timestamp': packet.time,
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'payload': payload,
            'seq': seq,
            'ack': ack,
            'flags': flags,
            'direction': 'client->server' if is_client_to_server else 'server->client'
        })

class HTTPParser:
    def __init__(self):
        self.tcp_streams = defaultdict(TCPStream)
    
    def process_packets(self, packets):
        for packet in packets:
            self.process_packet(packet)
    
    def process_packet(self, packet):
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return
        
        ip = packet[IP]
        tcp = packet[TCP]
        
        src_ip = ip.src
        dst_ip = ip.dst
        src_port = tcp.sport
        dst_port = tcp.dport
        
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            stream_key = (src_ip, src_port, dst_ip, dst_port)
            client = (src_ip, src_port)
            server = (dst_ip, dst_port)
        else:
            stream_key = (dst_ip, dst_port, src_ip, src_port)
            client = (dst_ip, dst_port)
            server = (src_ip, src_port)
        
        if not hasattr(self.tcp_streams[stream_key], 'client'):
            self.tcp_streams[stream_key].client = client
            self.tcp_streams[stream_key].server = server
        
        payload = bytes(tcp.payload) if packet.haslayer(Raw) else b""
        
        self.tcp_streams[stream_key].add_packet(
            packet, src_ip, src_port, dst_ip, dst_port,
            payload, tcp.seq, tcp.ack, tcp.flags
        )
    
    def extract_http_conversations(self):
        conversations = []
        
        for stream_key, stream in self.tcp_streams.items():
            if not stream.client_data and not stream.server_data:
                continue
            
            client_requests = self.parse_http_data(stream.client_data, 'request')
            server_responses = self.parse_http_data(stream.server_data, 'response')
            
            if client_requests or server_responses:
                conversation = {
                    'client': stream.client,
                    'server': stream.server,
                    'timestamp': stream.packets[0]['timestamp'] if stream.packets else 0,
                    'requests': client_requests,
                    'responses': server_responses
                }
                conversations.append(conversation)
        
        return conversations
    
    def parse_http_data(self, data, direction):
        if not data:
            return []
        
        try:
            text = data.decode('utf-8', errors='ignore')
        except:
            return []
        
        messages = []
        
        if direction == 'request':
            pattern = r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT) [^\r\n]* HTTP/\d\.\d'
        else:
            pattern = r'HTTP/\d\.\d \d{3} [^\r\n]*'
        
        matches = list(re.finditer(pattern, text))
        
        for i, match in enumerate(matches):
            start = match.start()
            end = matches[i + 1].start() if i < len(matches) - 1 else len(text)
            
            message_text = text[start:end].strip()
            if message_text:
                message = self.parse_single_http_message(message_text, direction)
                if message:
                    messages.append(message)
        
        return messages
    
    def parse_single_http_message(self, message_text, direction):
        lines = message_text.split('\r\n')
        if not lines:
            return None
        
        first_line = lines[0].strip()
        
        if direction == 'request':
            parts = first_line.split(' ')
            if len(parts) < 3:
                return None
            
            method, path, version = parts[0], parts[1], ' '.join(parts[2:])
            
            headers = {}
            body = None
            body_started = False
            
            for line in lines[1:]:
                if not line.strip() and not body_started:
                    body_started = True
                    continue
                
                if body_started:
                    body = line if body is None else body + '\r\n' + line
                elif ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key] = value
            
            return {
                'type': 'request',
                'method': method,
                'path': path,
                'version': version,
                'headers': headers,
                'body': body,
                'raw': message_text
            }
        
        else:
            parts = first_line.split(' ', 2)
            if len(parts) < 3:
                return None
            
            version, status_code, status_text = parts[0], parts[1], parts[2]
            
            headers = {}
            body = None
            body_started = False
            
            for line in lines[1:]:
                if not line.strip() and not body_started:
                    body_started = True
                    continue
                
                if body_started:
                    body = line if body is None else body + '\r\n' + line
                elif ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key] = value
            
            return {
                'type': 'response',
                'version': version,
                'status_code': status_code,
                'status_text': status_text,
                'headers': headers,
                'body': body,
                'raw': message_text
            }

# Color codes for terminal
class Colors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_conversations(conversations):
    """Print HTTP conversations in clean format"""
    for i, conv in enumerate(conversations, 1):
        print(f"\n{Colors.BLUE}{'=' * 80}{Colors.END}")
        print(f"{Colors.BLUE}HTTP CONVERSATION #{i}{Colors.END}")
        print(f"{Colors.BLUE}{'=' * 80}{Colors.END}")
        print(f"Client: {conv['client'][0]}:{conv['client'][1]}") 
        print(f"Server: {conv['server'][0]}:{conv['server'][1]}")
        print(f"Timestamp: {conv['timestamp']}")
        print(f"{Colors.BOLD}{'-' * 80}{Colors.END}")
        
        max_pairs = max(len(conv['requests']), len(conv['responses']))
        
        for pair_num in range(max_pairs):
            # Print request
            if pair_num < len(conv['requests']):
                req = conv['requests'][pair_num]
                print(f"\n{Colors.GREEN}REQUEST #{pair_num + 1}:{Colors.END}")
                print("-" * 80)
                print(req['raw'])
                print("-" * 80)
            
            # Print response  
            if pair_num < len(conv['responses']):
                resp = conv['responses'][pair_num]
                print(f"\n{Colors.YELLOW}RESPONSE #{pair_num + 1}:{Colors.END}")
                print("-" * 80)
                print(resp['raw'])
                print("-" * 80)
        
        print(f"\n{Colors.BLUE}END OF CONVERSATION #{i}{Colors.END}")
        print(f"{Colors.BLUE}{'=' * 80}{Colors.END}")

def main():
    parser = argparse.ArgumentParser(description='PCAPNG HTTP Parser - Clean Output')
    parser.add_argument('file', help='PCAPNG file to parse')
    parser.add_argument('--no-colors', action='store_true', help='Disable colors')
    
    args = parser.parse_args()
    
    # Disable colors if requested
    if args.no_colors:
        for color in dir(Colors):
            if not color.startswith('_'):
                setattr(Colors, color, '')
    
    print("PCAPNG HTTP Parser")
    print("Extracting HTTP conversations...")
    print()
    
    try:
        packets = rdpcap(args.file)
        print(f"Loaded: {args.file}")
        print(f"Total packets: {len(packets)}")
        
        http_parser = HTTPParser()
        http_parser.process_packets(packets)
        conversations = http_parser.extract_http_conversations()
        
        print(f"\nFound {len(conversations)} HTTP conversations")
        
        if conversations:
            print_conversations(conversations)
        else:
            print("No HTTP conversations found!")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python http_parser.py <pcapng_file>")
        print("       python http_parser.py --no-colors <pcapng_file> for no colors")
        sys.exit(1)
    
    main()