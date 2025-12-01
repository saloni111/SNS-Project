"""
DNS Tunneling Detection Engine
My hybrid approach combining rules with ML for better detection
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple, Optional
import logging
import pickle
import os
from datetime import datetime

class DNSTunnelingDetector:
    """Main detection class - handles both rules and ML"""
    
    def __init__(self, model_path: str = "models/"):
        self.model_path = model_path
        self.logger = logging.getLogger(__name__)
        
        # Detection thresholds - I tuned these based on testing
        self.thresholds = {
            'max_entropy': 4.5,
            'max_label_length': 30,
            'max_subdomain_count': 5,
            'min_nxdomain_ratio': 0.3,
            'max_query_rate': 10.0,  # queries per minute
            'min_interval_cv': 0.05,  # for periodic detection
            'max_txt_ratio': 0.5,
            'min_domain_diversity': 0.8
        }
        
        # ML model components
        self.isolation_forest = None
        self.scaler = None
        self.feature_columns = None
        self.is_trained = False
        
        # Create model directory
        os.makedirs(model_path, exist_ok=True)
    
    def apply_rules(self, features: Dict) -> Tuple[bool, List[str], float]:
        """Run my detection rules and return alerts"""
        alerts = []
        score = 0.0
        
        # Check for high entropy - usually means encoded data
        if features.get('domain_entropy', 0) > self.thresholds['max_entropy']:
            alerts.append(f"High domain entropy: {features['domain_entropy']:.2f}")
            score += 0.3
        
        if features.get('max_label_entropy', 0) > self.thresholds['max_entropy']:
            alerts.append(f"High label entropy: {features['max_label_entropy']:.2f}")
            score += 0.2
        
        # Long subdomains are suspicious
        if features.get('max_label_length', 0) > self.thresholds['max_label_length']:
            alerts.append(f"Long subdomain: {features['max_label_length']} chars")
            score += 0.2
        
        # Too many subdomain levels
        if features.get('subdomain_count', 0) > self.thresholds['max_subdomain_count']:
            alerts.append(f"Many subdomains: {features['subdomain_count']}")
            score += 0.15
        
        # Too many failed DNS lookups suggests probing
        if features.get('nxdomain_ratio', 0) > self.thresholds['min_nxdomain_ratio']:
            alerts.append(f"High NXDOMAIN ratio: {features['nxdomain_ratio']:.2f}")
            score += 0.25
        
        # Suspicious query patterns
        if features.get('query_rate', 0) > self.thresholds['max_query_rate']:
            alerts.append(f"High query rate: {features['query_rate']:.1f}/min")
            score += 0.2
        
        # Periodic/beacon-like behavior
        if (features.get('interval_cv', 1.0) < self.thresholds['min_interval_cv'] and 
            features.get('is_periodic', False)):
            alerts.append(f"Periodic queries detected (CV: {features['interval_cv']:.3f})")
            score += 0.3
        
        # High TXT record usage (common in tunneling)
        if features.get('txt_record_ratio', 0) > self.thresholds['max_txt_ratio']:
            alerts.append(f"High TXT record usage: {features['txt_record_ratio']:.2f}")
            score += 0.2
        
        # High domain diversity (many unique subdomains)
        if features.get('domain_diversity', 0) > self.thresholds['min_domain_diversity']:
            alerts.append(f"High domain diversity: {features['domain_diversity']:.2f}")
            score += 0.15
        
        # Suspicious patterns
        if features.get('has_hex_pattern', False):
            alerts.append("Hexadecimal pattern detected")
            score += 0.1
        
        if features.get('has_base64_pattern', False):
            alerts.append("Base64 pattern detected")
            score += 0.15
        
        # Low TTL values (evasion technique)
        if features.get('low_ttl_ratio', 0) > 0.5:
            alerts.append(f"Many low TTL responses: {features['low_ttl_ratio']:.2f}")
            score += 0.1
        
        # Night-time activity
        if features.get('night_queries', 0) > 0.7:
            alerts.append(f"High night-time activity: {features['night_queries']:.2f}")
            score += 0.1
        
        is_suspicious = score > 0.5 or len(alerts) >= 3
        return is_suspicious, alerts, min(score, 1.0)
    
    def prepare_ml_features(self, features: Dict) -> Optional[np.ndarray]:
        """Prepare features for ML model"""
        if not self.feature_columns:
            return None
        
        # Select numerical features for ML
        ml_features = []
        for col in self.feature_columns:
            value = features.get(col, 0)
            # Convert boolean to int
            if isinstance(value, bool):
                value = int(value)
            ml_features.append(float(value))
        
        return np.array(ml_features).reshape(1, -1)
    
    def train_anomaly_detector(self, training_features: List[Dict], contamination: float = 0.1):
        """Train the Isolation Forest anomaly detector"""
        if not training_features:
            self.logger.error("No training data provided")
            return
        
        # Convert to DataFrame
        df = pd.DataFrame(training_features)
        
        # Select numerical features
        numerical_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        
        # Remove metadata columns
        exclude_cols = ['query_count', 'time_window_hours', 'analysis_timestamp']
        numerical_cols = [col for col in numerical_cols if col not in exclude_cols]
        
        if not numerical_cols:
            self.logger.error("No numerical features found for training")
            return
        
        self.feature_columns = numerical_cols
        X = df[numerical_cols].fillna(0)
        
        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        
        self.isolation_forest.fit(X_scaled)
        self.is_trained = True
        
        self.logger.info(f"Trained anomaly detector with {len(training_features)} samples")
        self.logger.info(f"Using features: {self.feature_columns}")
    
    def predict_anomaly(self, features: Dict) -> Tuple[bool, float]:
        """Predict if features represent anomalous behavior"""
        if not self.is_trained:
            return False, 0.0
        
        ml_features = self.prepare_ml_features(features)
        if ml_features is None:
            return False, 0.0
        
        try:
            # Scale features
            ml_features_scaled = self.scaler.transform(ml_features)
            
            # Predict anomaly
            prediction = self.isolation_forest.predict(ml_features_scaled)[0]
            anomaly_score = self.isolation_forest.decision_function(ml_features_scaled)[0]
            
            # Convert to probability-like score (0-1)
            # Isolation Forest returns negative scores for anomalies
            normalized_score = max(0, min(1, (0.5 - anomaly_score) / 1.0))
            
            is_anomaly = prediction == -1
            return is_anomaly, normalized_score
            
        except Exception as e:
            self.logger.error(f"Error in anomaly prediction: {e}")
            return False, 0.0
    
    def detect_tunneling(self, features: Dict) -> Dict:
        """Main detection function combining rules and ML"""
        detection_result = {
            'domain': features.get('domain', 'unknown'),
            'timestamp': datetime.now().isoformat(),
            'is_suspicious': False,
            'confidence': 0.0,
            'rule_alerts': [],
            'rule_score': 0.0,
            'ml_anomaly': False,
            'ml_score': 0.0,
            'explanation': []
        }
        
        # Apply rule-based detection
        rule_suspicious, rule_alerts, rule_score = self.apply_rules(features)
        detection_result.update({
            'rule_alerts': rule_alerts,
            'rule_score': rule_score
        })
        
        # Apply ML-based detection
        ml_anomaly, ml_score = self.predict_anomaly(features)
        detection_result.update({
            'ml_anomaly': ml_anomaly,
            'ml_score': ml_score
        })
        
        # Combine results
        combined_score = (rule_score * 0.7) + (ml_score * 0.3)  # Weight rules higher
        is_suspicious = rule_suspicious or (ml_anomaly and ml_score > 0.6)
        
        detection_result.update({
            'is_suspicious': is_suspicious,
            'confidence': combined_score
        })
        
        # Generate explanation
        explanation = []
        if rule_alerts:
            explanation.extend(rule_alerts)
        if ml_anomaly:
            explanation.append(f"ML anomaly detected (score: {ml_score:.2f})")
        
        detection_result['explanation'] = explanation
        
        return detection_result
    
    def batch_detect(self, features_list: List[Dict]) -> List[Dict]:
        """Run detection on multiple feature sets"""
        results = []
        for features in features_list:
            result = self.detect_tunneling(features)
            results.append(result)
        
        return results
    
    def save_model(self):
        """Save trained model components"""
        if not self.is_trained:
            self.logger.warning("No trained model to save")
            return
        
        try:
            model_data = {
                'isolation_forest': self.isolation_forest,
                'scaler': self.scaler,
                'feature_columns': self.feature_columns,
                'thresholds': self.thresholds
            }
            
            model_file = os.path.join(self.model_path, 'dns_detector.pkl')
            with open(model_file, 'wb') as f:
                pickle.dump(model_data, f)
            
            self.logger.info(f"Model saved to {model_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
    
    def load_model(self):
        """Load trained model components"""
        try:
            model_file = os.path.join(self.model_path, 'dns_detector.pkl')
            
            if not os.path.exists(model_file):
                self.logger.warning(f"Model file not found: {model_file}")
                return False
            
            with open(model_file, 'rb') as f:
                model_data = pickle.load(f)
            
            self.isolation_forest = model_data['isolation_forest']
            self.scaler = model_data['scaler']
            self.feature_columns = model_data['feature_columns']
            self.thresholds = model_data.get('thresholds', self.thresholds)
            self.is_trained = True
            
            self.logger.info(f"Model loaded from {model_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            return False
    
    def update_thresholds(self, new_thresholds: Dict):
        """Update rule-based detection thresholds"""
        self.thresholds.update(new_thresholds)
        self.logger.info("Detection thresholds updated")
    
    def get_detection_stats(self, results: List[Dict]) -> Dict:
        """Calculate detection statistics"""
        if not results:
            return {}
        
        total = len(results)
        suspicious = sum(1 for r in results if r['is_suspicious'])
        
        stats = {
            'total_analyzed': total,
            'suspicious_count': suspicious,
            'suspicious_rate': suspicious / total,
            'avg_confidence': np.mean([r['confidence'] for r in results]),
            'avg_rule_score': np.mean([r['rule_score'] for r in results]),
            'avg_ml_score': np.mean([r['ml_score'] for r in results]),
            'ml_anomalies': sum(1 for r in results if r['ml_anomaly'])
        }
        
        return stats