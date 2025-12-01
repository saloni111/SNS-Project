"""
DNS Traffic Data Generator
Creates realistic DNS traffic for testing my detection system
"""

import random
import string
import time
import sqlite3
from typing import List, Dict
import base64
import hashlib
from datetime import datetime, timedelta

class DNSTrafficGenerator:
    """Creates both normal and tunneling DNS queries for testing"""
    
    def __init__(self, db_path: str = "data/dns_traffic.db"):
        self.db_path = db_path
        
        # I use these domains to simulate normal browsing
        self.legitimate_domains = [
            "google.com", "facebook.com", "amazon.com", "microsoft.com",
            "apple.com", "netflix.com", "twitter.com", "linkedin.com",
            "github.com", "stackoverflow.com", "wikipedia.org", "reddit.com"
        ]
        
        # CDN and cloud service domains
        self.cdn_domains = [
            "cloudfront.net", "amazonaws.com", "azure.com", 
            "googleusercontent.com", "fastly.com", "cloudflare.com"
        ]
        
        # Common subdomains
        self.common_subdomains = [
            "www", "api", "cdn", "static", "images", "assets",
            "mail", "ftp", "blog", "shop", "admin", "dev"
        ]
    
    def generate_legitimate_traffic(self, count: int = 100) -> List[Dict]:
        """Generate legitimate DNS traffic"""
        traffic = []
        base_time = time.time() - 3600  # Start 1 hour ago
        
        for i in range(count):
            # Choose domain type
            if random.random() < 0.7:  # 70% main domains
                domain = random.choice(self.legitimate_domains)
                if random.random() < 0.3:  # 30% with subdomain
                    subdomain = random.choice(self.common_subdomains)
                    domain = f"{subdomain}.{domain}"
            else:  # 30% CDN/cloud domains
                base_domain = random.choice(self.cdn_domains)
                if random.random() < 0.5:
                    # Add random subdomain for CDN
                    subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
                    domain = f"{subdomain}.{base_domain}"
                else:
                    domain = base_domain
            
            # Generate query
            query = {
                'timestamp': base_time + i * random.uniform(1, 30),
                'src_ip': f"192.168.1.{random.randint(10, 200)}",
                'dst_ip': "8.8.8.8",
                'query_name': domain,
                'query_type': random.choices([1, 28, 5, 15], weights=[70, 15, 10, 5])[0],  # A, AAAA, CNAME, MX
                'response_code': random.choices([0, 3], weights=[95, 5])[0],  # Success, NXDOMAIN
                'response_data': self._generate_response_data(),
                'packet_size': random.randint(50, 200),
                'is_response': random.choice([True, False]),
                'ttl': random.randint(300, 86400)
            }
            
            traffic.append(query)
        
        return traffic
    
    def generate_tunneling_traffic(self, count: int = 50, tunnel_type: str = "data_exfil") -> List[Dict]:
        """Generate DNS tunneling traffic"""
        traffic = []
        base_time = time.time() - 1800  # Start 30 minutes ago
        
        # Choose base domain for tunneling
        base_domain = f"tunnel{random.randint(1000, 9999)}.com"
        
        for i in range(count):
            if tunnel_type == "data_exfil":
                query = self._generate_exfiltration_query(base_domain, base_time + i * random.uniform(5, 15))
            elif tunnel_type == "command_control":
                query = self._generate_c2_query(base_domain, base_time + i * random.uniform(10, 30))
            elif tunnel_type == "beacon":
                query = self._generate_beacon_query(base_domain, base_time + i * 60)  # Every minute
            else:
                query = self._generate_generic_tunnel_query(base_domain, base_time + i * random.uniform(3, 20))
            
            traffic.append(query)
        
        return traffic
    
    def _generate_exfiltration_query(self, base_domain: str, timestamp: float) -> Dict:
        """Generate data exfiltration DNS query"""
        # Simulate encoded data in subdomain
        data_chunk = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        encoded_data = base64.b64encode(data_chunk.encode()).decode().replace('=', '').replace('+', '-').replace('/', '_')
        
        # Split into multiple labels if too long
        if len(encoded_data) > 63:
            labels = [encoded_data[i:i+20] for i in range(0, len(encoded_data), 20)]
            subdomain = '.'.join(labels)
        else:
            subdomain = encoded_data
        
        domain = f"{subdomain}.{base_domain}"
        
        return {
            'timestamp': timestamp,
            'src_ip': f"192.168.1.{random.randint(50, 100)}",
            'dst_ip': "1.1.1.1",
            'query_name': domain,
            'query_type': 16,  # TXT record for data exfiltration
            'response_code': random.choices([0, 3], weights=[60, 40])[0],  # Higher NXDOMAIN rate
            'response_data': self._generate_response_data(),
            'packet_size': random.randint(100, 400),
            'is_response': False,
            'ttl': random.randint(60, 300)  # Lower TTL
        }
    
    def _generate_c2_query(self, base_domain: str, timestamp: float) -> Dict:
        """Generate command and control DNS query"""
        # Simulate command ID or session identifier
        session_id = hashlib.md5(str(timestamp).encode()).hexdigest()[:16]
        command_id = random.randint(1000, 9999)
        
        domain = f"{session_id}.{command_id}.{base_domain}"
        
        return {
            'timestamp': timestamp,
            'src_ip': f"192.168.1.{random.randint(50, 100)}",
            'dst_ip': "8.8.4.4",
            'query_name': domain,
            'query_type': 1,  # A record
            'response_code': 0,
            'response_data': f"192.168.100.{random.randint(1, 254)}",  # C2 server IP
            'packet_size': random.randint(80, 250),
            'is_response': True,
            'ttl': random.randint(30, 120)  # Very low TTL
        }
    
    def _generate_beacon_query(self, base_domain: str, timestamp: float) -> Dict:
        """Generate periodic beacon DNS query"""
        # Simple beacon with timestamp
        beacon_id = int(timestamp) % 10000
        
        domain = f"beacon.{beacon_id}.{base_domain}"
        
        return {
            'timestamp': timestamp,
            'src_ip': f"192.168.1.{random.randint(50, 100)}",
            'dst_ip': "8.8.8.8",
            'query_name': domain,
            'query_type': 1,
            'response_code': 3,  # NXDOMAIN for beacon
            'response_data': "",
            'packet_size': random.randint(60, 120),
            'is_response': False,
            'ttl': 0
        }
    
    def _generate_generic_tunnel_query(self, base_domain: str, timestamp: float) -> Dict:
        """Generate generic tunneling query with high entropy"""
        # High entropy subdomain
        entropy_data = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(20, 40)))
        
        domain = f"{entropy_data}.{base_domain}"
        
        return {
            'timestamp': timestamp,
            'src_ip': f"192.168.1.{random.randint(50, 100)}",
            'dst_ip': "1.1.1.1",
            'query_name': domain,
            'query_type': random.choice([1, 16]),
            'response_code': random.choices([0, 3], weights=[70, 30])[0],
            'response_data': self._generate_response_data(),
            'packet_size': random.randint(90, 300),
            'is_response': random.choice([True, False]),
            'ttl': random.randint(60, 600)
        }
    
    def _generate_response_data(self) -> str:
        """Generate realistic DNS response data"""
        response_types = [
            lambda: f"192.168.{random.randint(1, 255)}.{random.randint(1, 254)}",  # IP
            lambda: f"2001:db8::{random.randint(1, 9999):x}",  # IPv6
            lambda: f"mail{random.randint(1, 5)}.example.com",  # MX record
            lambda: "",  # Empty response
        ]
        
        return random.choice(response_types)()
    
    def store_traffic(self, traffic: List[Dict]):
        """Store generated traffic in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Ensure table exists
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
            
            # Insert traffic
            for query in traffic:
                cursor.execute('''
                    INSERT INTO dns_queries 
                    (timestamp, src_ip, dst_ip, query_name, query_type, 
                     response_code, response_data, packet_size, is_response, ttl)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    query['timestamp'],
                    query['src_ip'],
                    query['dst_ip'],
                    query['query_name'],
                    query['query_type'],
                    query['response_code'],
                    query['response_data'],
                    query['packet_size'],
                    query['is_response'],
                    query['ttl']
                ))
            
            conn.commit()
            conn.close()
            
            print(f"Stored {len(traffic)} DNS queries in database")
            
        except Exception as e:
            print(f"Error storing traffic: {e}")
    
    def generate_mixed_dataset(self, legitimate_count: int = 500, tunneling_count: int = 100):
        """Generate a mixed dataset of legitimate and tunneling traffic"""
        print("Generating legitimate traffic...")
        legitimate_traffic = self.generate_legitimate_traffic(legitimate_count)
        
        print("Generating tunneling traffic...")
        tunneling_traffic = []
        
        # Mix different types of tunneling
        tunneling_traffic.extend(self.generate_tunneling_traffic(tunneling_count // 4, "data_exfil"))
        tunneling_traffic.extend(self.generate_tunneling_traffic(tunneling_count // 4, "command_control"))
        tunneling_traffic.extend(self.generate_tunneling_traffic(tunneling_count // 4, "beacon"))
        tunneling_traffic.extend(self.generate_tunneling_traffic(tunneling_count // 4, "generic"))
        
        # Combine and shuffle
        all_traffic = legitimate_traffic + tunneling_traffic
        random.shuffle(all_traffic)
        
        print(f"Generated {len(all_traffic)} total DNS queries")
        print(f"- Legitimate: {len(legitimate_traffic)}")
        print(f"- Tunneling: {len(tunneling_traffic)}")
        
        return all_traffic, len(tunneling_traffic)

def main():
    """Generate sample data for testing"""
    import os
    
    # Create data directory
    os.makedirs("data", exist_ok=True)
    
    generator = DNSTrafficGenerator()
    
    print("Generating mixed DNS traffic dataset...")
    traffic, tunneling_count = generator.generate_mixed_dataset(
        legitimate_count=800,
        tunneling_count=200
    )
    
    generator.store_traffic(traffic)
    
    print(f"\n✅ Dataset generation complete!")
    print(f"Total queries: {len(traffic)}")
    print(f"Tunneling queries: {tunneling_count}")
    print(f"Ground truth tunneling rate: {tunneling_count/len(traffic):.1%}")

if __name__ == "__main__":
    main()