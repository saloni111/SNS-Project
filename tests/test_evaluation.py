"""
Evaluation Framework for DNS Tunneling Detection
My testing code to measure how well the system works
"""

import sys
import os
import unittest
import pandas as pd
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.features.extractor import DNSFeatureExtractor
from src.detection.detector import DNSTunnelingDetector
from src.utils.data_generator import DNSTrafficGenerator

class DNSDetectionEvaluator:
    """Evaluate DNS tunneling detection performance"""
    
    def __init__(self):
        self.generator = DNSTrafficGenerator("data/test_dns_traffic.db")
        self.extractor = DNSFeatureExtractor("data/test_dns_traffic.db")
        self.detector = DNSTunnelingDetector("models/test/")
        
        # Create test model directory
        os.makedirs("models/test", exist_ok=True)
    
    def generate_evaluation_dataset(self, legitimate_count: int = 400, tunneling_count: int = 100):
        """Generate labeled dataset for evaluation"""
        print("Generating evaluation dataset...")
        
        # Generate traffic
        legitimate_traffic = self.generator.generate_legitimate_traffic(legitimate_count)
        tunneling_traffic = []
        
        # Generate different types of tunneling traffic
        tunneling_traffic.extend(self.generator.generate_tunneling_traffic(tunneling_count // 4, "data_exfil"))
        tunneling_traffic.extend(self.generator.generate_tunneling_traffic(tunneling_count // 4, "command_control"))
        tunneling_traffic.extend(self.generator.generate_tunneling_traffic(tunneling_count // 4, "beacon"))
        tunneling_traffic.extend(self.generator.generate_tunneling_traffic(tunneling_count // 4, "generic"))
        
        # Store traffic
        all_traffic = legitimate_traffic + tunneling_traffic
        self.generator.store_traffic(all_traffic)
        
        # Create ground truth labels
        ground_truth = {}
        
        # Label legitimate domains
        for query in legitimate_traffic:
            domain = query['query_name']
            ground_truth[domain] = 0  # Legitimate
        
        # Label tunneling domains
        for query in tunneling_traffic:
            domain = query['query_name']
            ground_truth[domain] = 1  # Tunneling
        
        print(f"Generated {len(all_traffic)} queries:")
        print(f"  Legitimate: {legitimate_count}")
        print(f"  Tunneling: {len(tunneling_traffic)}")
        print(f"  Unique domains: {len(ground_truth)}")
        
        return ground_truth
    
    def extract_features_for_evaluation(self, ground_truth: dict):
        """Extract features for all domains in ground truth"""
        print("Extracting features for evaluation...")
        
        features_list = []
        labels = []
        
        for domain, label in ground_truth.items():
            features = self.extractor.extract_features_for_domain(domain, time_window_hours=24)
            
            if features and features.get('query_count', 0) > 0:
                features_list.append(features)
                labels.append(label)
        
        print(f"Extracted features for {len(features_list)} domains")
        return features_list, labels
    
    def train_and_evaluate(self, features_list: list, labels: list, test_split: float = 0.3):
        """Train model and evaluate performance"""
        print("Training and evaluating model...")
        
        # Split data
        n_test = int(len(features_list) * test_split)
        indices = np.random.permutation(len(features_list))
        
        train_indices = indices[n_test:]
        test_indices = indices[:n_test]
        
        train_features = [features_list[i] for i in train_indices]
        test_features = [features_list[i] for i in test_indices]
        test_labels = [labels[i] for i in test_indices]
        
        print(f"Training set: {len(train_features)} samples")
        print(f"Test set: {len(test_features)} samples")
        
        # Train model (using only legitimate data for unsupervised learning)
        legitimate_train_features = [f for i, f in enumerate(train_features) if labels[train_indices[i]] == 0]
        
        if len(legitimate_train_features) < 10:
            print("❌ Insufficient legitimate training data")
            return None
        
        # Estimate contamination rate from training data
        train_labels = [labels[i] for i in train_indices]
        contamination_rate = sum(train_labels) / len(train_labels)
        
        # Cap contamination rate at 0.4 (Isolation Forest limit is 0.5)
        contamination_rate = min(contamination_rate, 0.4)
        
        print(f"Estimated contamination rate: {contamination_rate:.2%}")
        
        # Train with all training data (including some tunneling for realistic contamination)
        self.detector.train_anomaly_detector(train_features, contamination=contamination_rate)
        
        # Evaluate on test set
        results = self.detector.batch_detect(test_features)
        predictions = [1 if r['is_suspicious'] else 0 for r in results]
        
        # Calculate metrics
        precision = precision_score(test_labels, predictions)
        recall = recall_score(test_labels, predictions)
        f1 = f1_score(test_labels, predictions)
        
        # Confusion matrix
        cm = confusion_matrix(test_labels, predictions)
        
        evaluation_results = {
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'confusion_matrix': cm,
            'test_labels': test_labels,
            'predictions': predictions,
            'results': results,
            'contamination_rate': contamination_rate
        }
        
        return evaluation_results
    
    def print_evaluation_results(self, eval_results: dict):
        """Print detailed evaluation results"""
        print("\n" + "="*50)
        print("EVALUATION RESULTS")
        print("="*50)
        
        print(f"Precision: {eval_results['precision']:.3f}")
        print(f"Recall: {eval_results['recall']:.3f}")
        print(f"F1-Score: {eval_results['f1_score']:.3f}")
        print(f"Contamination Rate: {eval_results['contamination_rate']:.2%}")
        
        print("\nConfusion Matrix:")
        cm = eval_results['confusion_matrix']
        print(f"                Predicted")
        print(f"                Legit  Tunnel")
        print(f"Actual Legit    {cm[0,0]:5d}  {cm[0,1]:6d}")
        print(f"       Tunnel   {cm[1,0]:5d}  {cm[1,1]:6d}")
        
        # Calculate additional metrics
        tn, fp, fn, tp = cm.ravel()
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        accuracy = (tp + tn) / (tp + tn + fp + fn)
        
        print(f"\nAdditional Metrics:")
        print(f"Accuracy: {accuracy:.3f}")
        print(f"Specificity: {specificity:.3f}")
        print(f"False Positive Rate: {fp/(fp+tn):.3f}")
        print(f"False Negative Rate: {fn/(fn+tp):.3f}")
        
        # Analyze detection confidence
        results = eval_results['results']
        test_labels = eval_results['test_labels']
        
        legitimate_confidences = [r['confidence'] for i, r in enumerate(results) if test_labels[i] == 0]
        tunneling_confidences = [r['confidence'] for i, r in enumerate(results) if test_labels[i] == 1]
        
        print(f"\nConfidence Score Analysis:")
        print(f"Legitimate domains - Mean: {np.mean(legitimate_confidences):.3f}, Std: {np.std(legitimate_confidences):.3f}")
        print(f"Tunneling domains - Mean: {np.mean(tunneling_confidences):.3f}, Std: {np.std(tunneling_confidences):.3f}")
    
    def analyze_feature_importance(self, features_list: list, labels: list):
        """Analyze which features are most discriminative"""
        print("\nFeature Importance Analysis:")
        print("-" * 30)
        
        df = pd.DataFrame(features_list)
        df['label'] = labels
        
        # Select numerical features
        numerical_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        numerical_cols = [col for col in numerical_cols if col not in ['query_count', 'time_window_hours']]
        
        # Calculate feature statistics by class
        legitimate_stats = df[df['label'] == 0][numerical_cols].mean()
        tunneling_stats = df[df['label'] == 1][numerical_cols].mean()
        
        # Calculate discrimination ratio
        discrimination_ratios = {}
        for col in numerical_cols:
            if legitimate_stats[col] != 0:
                ratio = abs(tunneling_stats[col] - legitimate_stats[col]) / legitimate_stats[col]
                discrimination_ratios[col] = ratio
        
        # Sort by discrimination power
        sorted_features = sorted(discrimination_ratios.items(), key=lambda x: x[1], reverse=True)
        
        print("Top discriminative features:")
        for feature, ratio in sorted_features[:10]:
            legit_val = legitimate_stats[feature]
            tunnel_val = tunneling_stats[feature]
            print(f"{feature:25s}: Legit={legit_val:6.3f}, Tunnel={tunnel_val:6.3f}, Ratio={ratio:6.3f}")
    
    def run_full_evaluation(self):
        """Run complete evaluation pipeline"""
        print("🧪 Running Full Evaluation Pipeline")
        print("=" * 50)
        
        # Generate evaluation dataset
        ground_truth = self.generate_evaluation_dataset(
            legitimate_count=300,
            tunneling_count=100
        )
        
        # Extract features
        features_list, labels = self.extract_features_for_evaluation(ground_truth)
        
        if len(features_list) < 20:
            print("❌ Insufficient data for evaluation")
            return
        
        # Train and evaluate
        eval_results = self.train_and_evaluate(features_list, labels)
        
        if eval_results is None:
            print("❌ Evaluation failed")
            return
        
        # Print results
        self.print_evaluation_results(eval_results)
        
        # Feature analysis
        self.analyze_feature_importance(features_list, labels)
        
        return eval_results

class TestDNSDetection(unittest.TestCase):
    """Unit tests for DNS detection components"""
    
    def setUp(self):
        self.evaluator = DNSDetectionEvaluator()
    
    def test_feature_extraction(self):
        """Test feature extraction functionality"""
        # Generate small test dataset
        generator = DNSTrafficGenerator("data/test_features.db")
        traffic = generator.generate_legitimate_traffic(50)
        generator.store_traffic(traffic)
        
        # Extract features
        extractor = DNSFeatureExtractor("data/test_features.db")
        features = extractor.extract_batch_features(time_window_hours=24, min_queries=1)
        
        self.assertGreater(len(features), 0, "Should extract features from test data")
        
        # Check feature structure
        if features:
            feature_keys = features[0].keys()
            required_keys = ['domain', 'domain_entropy', 'query_count']
            for key in required_keys:
                self.assertIn(key, feature_keys, f"Feature {key} should be present")
    
    def test_detection_rules(self):
        """Test rule-based detection"""
        detector = DNSTunnelingDetector()
        
        # Test with high entropy domain (should be suspicious)
        high_entropy_features = {
            'domain': 'abc123xyz789.example.com',
            'domain_entropy': 5.0,
            'max_label_length': 35,
            'nxdomain_ratio': 0.8,
            'query_count': 10
        }
        
        result = detector.detect_tunneling(high_entropy_features)
        self.assertTrue(result['is_suspicious'], "High entropy domain should be flagged")
        self.assertGreater(len(result['rule_alerts']), 0, "Should have rule alerts")
        
        # Test with normal domain (should not be suspicious)
        normal_features = {
            'domain': 'www.google.com',
            'domain_entropy': 2.5,
            'max_label_length': 6,
            'nxdomain_ratio': 0.05,
            'query_count': 10
        }
        
        result = detector.detect_tunneling(normal_features)
        self.assertFalse(result['is_suspicious'], "Normal domain should not be flagged")
    
    def test_data_generation(self):
        """Test synthetic data generation"""
        generator = DNSTrafficGenerator("data/test_generation.db")
        
        # Generate legitimate traffic
        legitimate = generator.generate_legitimate_traffic(10)
        self.assertEqual(len(legitimate), 10, "Should generate requested number of queries")
        
        # Generate tunneling traffic
        tunneling = generator.generate_tunneling_traffic(5, "data_exfil")
        self.assertEqual(len(tunneling), 5, "Should generate requested tunneling queries")
        
        # Check query structure
        for query in legitimate + tunneling:
            required_fields = ['timestamp', 'query_name', 'query_type']
            for field in required_fields:
                self.assertIn(field, query, f"Query should have {field} field")

def main():
    """Run evaluation or tests"""
    import argparse
    
    parser = argparse.ArgumentParser(description="DNS Detection Evaluation")
    parser.add_argument('--mode', choices=['evaluate', 'test'], default='evaluate',
                       help='Run evaluation or unit tests')
    
    args = parser.parse_args()
    
    if args.mode == 'evaluate':
        evaluator = DNSDetectionEvaluator()
        evaluator.run_full_evaluation()
    else:
        unittest.main(argv=[''])

if __name__ == "__main__":
    main()