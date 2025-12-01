"""
DNS Feature Extraction Module
Calculates the features I use to spot tunneling patterns
"""

import re
import math
import sqlite3
import pandas as pd
import numpy as np
from collections import Counter, defaultdict
from typing import Dict, List, Tuple
import logging
from datetime import datetime, timedelta

class DNSFeatureExtractor:
    """Main feature extraction class - this is where I analyze DNS patterns"""
    
    def __init__(self, db_path: str = "data/dns_traffic.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        
        # I maintain lists of legitimate domains to reduce false positives
        self.legitimate_tlds = {
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int',
            'co.uk', 'co.jp', 'de', 'fr', 'it', 'es', 'ru'
        }
        
        # Known CDN and cloud service patterns
        self.cdn_patterns = [
            r'.*\.cloudfront\.net$',
            r'.*\.amazonaws\.com$',
            r'.*\.azure\.com$',
            r'.*\.googleusercontent\.com$',
            r'.*\.fastly\.com$',
            r'.*\.cloudflare\.com$'
        ]
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(text.lower())
        text_len = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def extract_subdomain_features(self, domain: str) -> Dict:
        """Extract features from domain/subdomain structure"""
        features = {}
        
        # Split domain into parts
        parts = domain.lower().split('.')
        
        # Basic structure features
        features['subdomain_count'] = len(parts) - 2 if len(parts) > 2 else 0
        features['total_length'] = len(domain)
        features['max_label_length'] = max(len(part) for part in parts) if parts else 0
        features['avg_label_length'] = np.mean([len(part) for part in parts]) if parts else 0
        
        # Entropy features
        features['domain_entropy'] = self.calculate_entropy(domain)
        features['max_label_entropy'] = max(self.calculate_entropy(part) for part in parts) if parts else 0
        
        # Character composition
        total_chars = len(domain.replace('.', ''))
        if total_chars > 0:
            features['digit_ratio'] = sum(c.isdigit() for c in domain) / total_chars
            features['vowel_ratio'] = sum(c in 'aeiou' for c in domain.lower()) / total_chars
            features['consonant_ratio'] = sum(c.isalpha() and c not in 'aeiou' for c in domain.lower()) / total_chars
            features['special_char_ratio'] = sum(not c.isalnum() and c != '.' for c in domain) / total_chars
        else:
            features.update({
                'digit_ratio': 0, 'vowel_ratio': 0, 
                'consonant_ratio': 0, 'special_char_ratio': 0
            })
        
        # Suspicious patterns
        features['has_long_subdomain'] = any(len(part) > 20 for part in parts[:-2])
        features['has_hex_pattern'] = bool(re.search(r'[0-9a-f]{8,}', domain.lower()))
        features['has_base64_pattern'] = bool(re.search(r'[A-Za-z0-9+/]{10,}={0,2}', domain))
        
        # Legitimate domain indicators
        features['is_known_tld'] = any(domain.endswith('.' + tld) for tld in self.legitimate_tlds)
        features['is_cdn_domain'] = any(re.match(pattern, domain) for pattern in self.cdn_patterns)
        
        return features
    
    def extract_temporal_features(self, queries: List[Dict], window_minutes: int = 5) -> Dict:
        """Extract temporal features from query patterns"""
        if not queries:
            return {}
        
        # Convert timestamps and sort
        timestamps = [q['timestamp'] for q in queries]
        timestamps.sort()
        
        features = {}
        
        # Basic temporal stats
        if len(timestamps) > 1:
            intervals = np.diff(timestamps)
            features['query_rate'] = len(queries) / (timestamps[-1] - timestamps[0]) * 60  # queries per minute
            features['avg_interval'] = np.mean(intervals)
            features['std_interval'] = np.std(intervals)
            features['min_interval'] = np.min(intervals)
            features['max_interval'] = np.max(intervals)
            
            # Regularity detection (beacon-like behavior)
            if len(intervals) > 2:
                # Coefficient of variation for interval regularity
                features['interval_cv'] = features['std_interval'] / features['avg_interval'] if features['avg_interval'] > 0 else 0
                
                # Check for periodic patterns
                features['is_periodic'] = features['interval_cv'] < 0.1 and features['avg_interval'] > 1
        else:
            features.update({
                'query_rate': 0, 'avg_interval': 0, 'std_interval': 0,
                'min_interval': 0, 'max_interval': 0, 'interval_cv': 0, 'is_periodic': False
            })
        
        # Time-based patterns
        hours = [datetime.fromtimestamp(ts).hour for ts in timestamps]
        features['unique_hours'] = len(set(hours))
        features['night_queries'] = sum(1 for h in hours if h < 6 or h > 22) / len(hours) if hours else 0
        
        return features
    
    def extract_response_features(self, queries: List[Dict]) -> Dict:
        """Extract features from DNS responses"""
        features = {}
        
        if not queries:
            return features
        
        # Response code analysis
        response_codes = [q.get('response_code', 0) for q in queries]
        total_queries = len(response_codes)
        
        features['nxdomain_ratio'] = sum(1 for code in response_codes if code == 3) / total_queries
        features['servfail_ratio'] = sum(1 for code in response_codes if code == 2) / total_queries
        features['success_ratio'] = sum(1 for code in response_codes if code == 0) / total_queries
        
        # Response size analysis
        response_sizes = [len(q.get('response_data', '')) for q in queries]
        if response_sizes:
            features['avg_response_size'] = np.mean(response_sizes)
            features['std_response_size'] = np.std(response_sizes)
            features['max_response_size'] = np.max(response_sizes)
            features['empty_response_ratio'] = sum(1 for size in response_sizes if size == 0) / len(response_sizes)
        
        # TTL analysis
        ttls = [q.get('ttl', 0) for q in queries if q.get('ttl', 0) > 0]
        if ttls:
            features['avg_ttl'] = np.mean(ttls)
            features['min_ttl'] = np.min(ttls)
            features['low_ttl_ratio'] = sum(1 for ttl in ttls if ttl < 300) / len(ttls)
        
        return features
    
    def extract_traffic_features(self, queries: List[Dict]) -> Dict:
        """Extract traffic volume and pattern features"""
        features = {}
        
        if not queries:
            return features
        
        # Unique domain analysis
        domains = [q.get('query_name', '') for q in queries]
        unique_domains = set(domains)
        
        features['unique_domain_count'] = len(unique_domains)
        features['domain_diversity'] = len(unique_domains) / len(domains) if domains else 0
        
        # Query type analysis
        query_types = [q.get('query_type', 1) for q in queries]
        type_counts = Counter(query_types)
        
        features['query_type_diversity'] = len(type_counts)
        features['a_record_ratio'] = type_counts.get(1, 0) / len(query_types)  # A records
        features['txt_record_ratio'] = type_counts.get(16, 0) / len(query_types)  # TXT records
        features['unusual_type_ratio'] = sum(count for qtype, count in type_counts.items() 
                                           if qtype not in [1, 2, 5, 15, 16, 28]) / len(query_types)
        
        # Packet size analysis
        packet_sizes = [q.get('packet_size', 0) for q in queries]
        if packet_sizes:
            features['avg_packet_size'] = np.mean(packet_sizes)
            features['std_packet_size'] = np.std(packet_sizes)
            features['large_packet_ratio'] = sum(1 for size in packet_sizes if size > 512) / len(packet_sizes)
        
        return features
    
    def extract_features_for_domain(self, domain: str, time_window_hours: int = 1) -> Dict:
        """Extract comprehensive features for a specific domain"""
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Get queries for this domain within time window
            end_time = datetime.now().timestamp()
            start_time = end_time - (time_window_hours * 3600)
            
            query = '''
                SELECT * FROM dns_queries 
                WHERE query_name LIKE ? AND timestamp BETWEEN ? AND ?
                ORDER BY timestamp
            '''
            
            df = pd.read_sql_query(query, conn, params=(f'%{domain}%', start_time, end_time))
            conn.close()
            
            if df.empty:
                return {}
            
            queries = df.to_dict('records')
            
            # Extract all feature categories
            features = {}
            features.update(self.extract_subdomain_features(domain))
            features.update(self.extract_temporal_features(queries))
            features.update(self.extract_response_features(queries))
            features.update(self.extract_traffic_features(queries))
            
            # Add metadata
            features['domain'] = domain
            features['query_count'] = len(queries)
            features['time_window_hours'] = time_window_hours
            features['analysis_timestamp'] = datetime.now().isoformat()
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting features for domain {domain}: {e}")
            return {}
    
    def extract_batch_features(self, time_window_hours: int = 1, min_queries: int = 5) -> List[Dict]:
        """Extract features for all domains with sufficient activity"""
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Get domains with sufficient query volume
            end_time = datetime.now().timestamp()
            start_time = end_time - (time_window_hours * 3600)
            
            query = '''
                SELECT query_name, COUNT(*) as query_count
                FROM dns_queries 
                WHERE timestamp BETWEEN ? AND ?
                GROUP BY query_name
                HAVING COUNT(*) >= ?
                ORDER BY query_count DESC
            '''
            
            df = pd.read_sql_query(query, conn, params=(start_time, end_time, min_queries))
            conn.close()
            
            # Extract features for each domain
            all_features = []
            for _, row in df.iterrows():
                domain_features = self.extract_features_for_domain(row['query_name'], time_window_hours)
                if domain_features:
                    all_features.append(domain_features)
            
            return all_features
            
        except Exception as e:
            self.logger.error(f"Error extracting batch features: {e}")
            return []