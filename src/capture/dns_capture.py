"""
DNS Traffic Capture Module
Handles capturing DNS packets and storing them for analysis
"""

import time
import sqlite3
from datetime import datetime
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP
from typing import Dict, List, Optional, Callable
import threading
import queue
import logging

class DNSCapture:
    """Main capture class - grabs DNS packets and stores them"""
    
    def __init__(self, db_path: str = "data/dns_traffic.db"):
        self.db_path = db_path
        self.packet_queue = queue.Queue()
        self.is_capturing = False
        self.capture_thread = None
        self.setup_database()
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    def setup_database(self):
        """Initialize SQLite database for storing DNS traffic"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                query_name TEXT,
                query_type TEXT,
                response_code INTEGER,
                response_data TEXT,
                packet_size INTEGER,
                is_response BOOLEAN,
                ttl INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def parse_dns_packet(self, packet) -> Optional[Dict]:
        """Parse DNS packet and extract relevant information"""
        try:
            if not packet.haslayer(DNS):
                return None
            
            dns_layer = packet[DNS]
            ip_layer = packet[IP] if packet.haslayer(IP) else None
            
            # Basic packet info
            packet_info = {
                'timestamp': time.time(),
                'src_ip': ip_layer.src if ip_layer else 'unknown',
                'dst_ip': ip_layer.dst if ip_layer else 'unknown',
                'packet_size': len(packet),
                'is_response': dns_layer.qr == 1,
                'response_code': dns_layer.rcode if hasattr(dns_layer, 'rcode') else 0
            }
            
            # Query information
            if dns_layer.qd:  # Query section
                query = dns_layer.qd
                packet_info.update({
                    'query_name': query.qname.decode('utf-8').rstrip('.'),
                    'query_type': query.qtype
                })
            
            # Response information
            response_data = []
            ttl = 0
            if dns_layer.an:  # Answer section
                for answer in dns_layer.an:
                    if hasattr(answer, 'rdata'):
                        response_data.append(str(answer.rdata))
                    if hasattr(answer, 'ttl'):
                        ttl = answer.ttl
            
            packet_info.update({
                'response_data': ';'.join(response_data),
                'ttl': ttl
            })
            
            return packet_info
            
        except Exception as e:
            self.logger.error(f"Error parsing DNS packet: {e}")
            return None
    
    def store_packet(self, packet_info: Dict):
        """Store parsed packet information in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO dns_queries 
                (timestamp, src_ip, dst_ip, query_name, query_type, 
                 response_code, response_data, packet_size, is_response, ttl)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                packet_info['timestamp'],
                packet_info['src_ip'],
                packet_info['dst_ip'],
                packet_info.get('query_name', ''),
                packet_info.get('query_type', 0),
                packet_info['response_code'],
                packet_info.get('response_data', ''),
                packet_info['packet_size'],
                packet_info['is_response'],
                packet_info.get('ttl', 0)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error storing packet: {e}")
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        packet_info = self.parse_dns_packet(packet)
        if packet_info:
            self.packet_queue.put(packet_info)
    
    def process_packets(self):
        """Process packets from queue and store in database"""
        while self.is_capturing or not self.packet_queue.empty():
            try:
                packet_info = self.packet_queue.get(timeout=1)
                self.store_packet(packet_info)
                self.packet_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error processing packet: {e}")
    
    def start_capture(self, interface: str = None, filter_str: str = "port 53"):
        """Start capturing DNS traffic"""
        if self.is_capturing:
            self.logger.warning("Capture already in progress")
            return
        
        self.is_capturing = True
        self.logger.info(f"Starting DNS capture on interface: {interface or 'all'}")
        
        # Start packet processing thread
        processing_thread = threading.Thread(target=self.process_packets)
        processing_thread.daemon = True
        processing_thread.start()
        
        try:
            # Start packet capture
            sniff(
                iface=interface,
                filter=filter_str,
                prn=self.packet_handler,
                stop_filter=lambda x: not self.is_capturing
            )
        except Exception as e:
            self.logger.error(f"Error during capture: {e}")
        finally:
            self.is_capturing = False
    
    def stop_capture(self):
        """Stop DNS traffic capture"""
        self.logger.info("Stopping DNS capture")
        self.is_capturing = False
    
    def load_pcap(self, pcap_file: str):
        """Load and process DNS traffic from pcap file"""
        self.logger.info(f"Loading DNS traffic from {pcap_file}")
        
        try:
            from scapy.all import rdpcap
            packets = rdpcap(pcap_file)
            
            processed = 0
            for packet in packets:
                packet_info = self.parse_dns_packet(packet)
                if packet_info:
                    self.store_packet(packet_info)
                    processed += 1
            
            self.logger.info(f"Processed {processed} DNS packets from {pcap_file}")
            
        except Exception as e:
            self.logger.error(f"Error loading pcap file: {e}")
    
    def get_recent_queries(self, limit: int = 100) -> List[Dict]:
        """Get recent DNS queries from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM dns_queries 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            columns = [desc[0] for desc in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return results
            
        except Exception as e:
            self.logger.error(f"Error retrieving queries: {e}")
            return []