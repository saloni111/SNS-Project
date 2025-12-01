"""
DNS Tunneling Detection System - Main Application
Command-line interface for my DNS detection system
"""

import os
import sys
import argparse
import logging
from datetime import datetime

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.capture.dns_capture import DNSCapture
from src.features.extractor import DNSFeatureExtractor
from src.detection.detector import DNSTunnelingDetector
from src.utils.data_generator import DNSTrafficGenerator

def setup_logging(log_level: str = "INFO"):
    """Setup logging configuration"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('dns_detection.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def create_directories():
    """Create necessary directories"""
    directories = ['data', 'models', 'logs']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)

def run_capture_mode(interface: str = None, pcap_file: str = None):
    """Run DNS traffic capture"""
    print("🔍 Starting DNS Traffic Capture...")
    
    capture = DNSCapture()
    
    try:
        if pcap_file:
            print(f"Loading traffic from {pcap_file}")
            capture.load_pcap(pcap_file)
        else:
            print(f"Starting live capture on interface: {interface or 'all'}")
            print("Press Ctrl+C to stop capture")
            capture.start_capture(interface=interface)
    except KeyboardInterrupt:
        print("\n Stopping capture...")
        capture.stop_capture()
    except Exception as e:
        print(f" Error during capture: {e}")

def run_analysis_mode(time_window: int = 1, min_queries: int = 5):
    """Run DNS traffic analysis"""
    print(" Starting DNS Traffic Analysis...")
    
    # Initialize components
    extractor = DNSFeatureExtractor()
    detector = DNSTunnelingDetector()
    
    # Try to load existing model
    if not detector.load_model():
        print("⚠️  No trained model found. Using rule-based detection only.")
    
    # Extract features
    print(f"Extracting features for domains with ≥{min_queries} queries in last {time_window}h...")
    features_list = extractor.extract_batch_features(
        time_window_hours=time_window,
        min_queries=min_queries
    )
    
    if not features_list:
        print(" No domains found with sufficient activity")
        return
    
    print(f" Extracted features for {len(features_list)} domains")
    
    # Run detection
    print(" Running detection analysis...")
    results = detector.batch_detect(features_list)
    
    # Filter suspicious results
    suspicious_results = [r for r in results if r['is_suspicious']]
    
    # Display results
    print(f"\n Detection Results:")
    print(f"Total analyzed: {len(results)}")
    print(f"Flagged as suspicious: {len(suspicious_results)}")
    print(f"Detection rate: {len(suspicious_results)/len(results):.1%}")
    
    if suspicious_results:
        print(f"\n Suspicious Domains Detected:")
        print("-" * 80)
        
        for result in suspicious_results[:10]:  # Show top 10
            print(f"\nDomain: {result['domain']}")
            print(f"Confidence: {result['confidence']:.2f}")
            print(f"Rule Score: {result['rule_score']:.2f} | ML Score: {result['ml_score']:.2f}")
            print("Alerts:")
            for alert in result['explanation']:
                print(f"  • {alert}")
    else:
        print("✅ No suspicious activity detected")

def run_training_mode(time_window: int = 24, contamination: float = 0.1):
    """Train the anomaly detection model"""
    print("🤖 Starting Model Training...")
    
    extractor = DNSFeatureExtractor()
    detector = DNSTunnelingDetector()
    
    # Extract training features
    print(f"Extracting training features from last {time_window} hours...")
    training_features = extractor.extract_batch_features(
        time_window_hours=time_window,
        min_queries=2  # Lower threshold for training
    )
    
    if len(training_features) < 20:
        print(f" Insufficient training data: {len(training_features)} domains")
        print("Need at least 20 domains for training")
        return
    
    print(f" Training on {len(training_features)} domains")
    
    # Train model
    detector.train_anomaly_detector(training_features, contamination=contamination)
    detector.save_model()
    
    print(" Model training completed and saved")

def run_generate_data_mode(legitimate: int = 500, tunneling: int = 100):
    """Generate synthetic test data"""
    print(" Generating Synthetic DNS Traffic...")
    
    generator = DNSTrafficGenerator()
    
    traffic, tunneling_count = generator.generate_mixed_dataset(
        legitimate_count=legitimate,
        tunneling_count=tunneling
    )
    
    generator.store_traffic(traffic)
    
    print(f" Generated {len(traffic)} DNS queries")
    print(f"   Legitimate: {legitimate}")
    print(f"   Tunneling: {tunneling_count}")

def run_dashboard_mode():
    """Launch the Streamlit dashboard"""
    print(" Starting Dashboard...")
    print("Dashboard will open in your browser at http://localhost:8501")
    
    try:
        import subprocess
        subprocess.run([
            sys.executable, "-m", "streamlit", "run", 
            "src/dashboard/app.py",
            "--server.port", "8501"
        ])
    except KeyboardInterrupt:
        print("\n⏹️  Dashboard stopped")
    except Exception as e:
        print(f" Error starting dashboard: {e}")
        print("Try running manually: streamlit run src/dashboard/app.py")

def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        description="DNS Tunneling Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py capture --interface eth0
  python main.py capture --pcap traffic.pcap
  python main.py analyze --time-window 6 --min-queries 10
  python main.py train --time-window 48 --contamination 0.15
  python main.py generate --legitimate 1000 --tunneling 200
  python main.py dashboard
        """
    )
    
    parser.add_argument('--log-level', default='INFO', 
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help='Set logging level')
    
    subparsers = parser.add_subparsers(dest='mode', help='Operation mode')
    
    # Capture mode
    capture_parser = subparsers.add_parser('capture', help='Capture DNS traffic')
    capture_parser.add_argument('--interface', help='Network interface to capture from')
    capture_parser.add_argument('--pcap', help='Load traffic from pcap file')
    
    # Analysis mode
    analysis_parser = subparsers.add_parser('analyze', help='Analyze DNS traffic')
    analysis_parser.add_argument('--time-window', type=int, default=1,
                                help='Analysis time window in hours (default: 1)')
    analysis_parser.add_argument('--min-queries', type=int, default=5,
                                help='Minimum queries per domain (default: 5)')
    
    # Training mode
    training_parser = subparsers.add_parser('train', help='Train detection model')
    training_parser.add_argument('--time-window', type=int, default=24,
                                help='Training data time window in hours (default: 24)')
    training_parser.add_argument('--contamination', type=float, default=0.1,
                                help='Expected contamination rate (default: 0.1)')
    
    # Data generation mode
    generate_parser = subparsers.add_parser('generate', help='Generate synthetic test data')
    generate_parser.add_argument('--legitimate', type=int, default=500,
                                help='Number of legitimate queries (default: 500)')
    generate_parser.add_argument('--tunneling', type=int, default=100,
                                help='Number of tunneling queries (default: 100)')
    
    # Dashboard mode
    subparsers.add_parser('dashboard', help='Launch web dashboard')
    
    args = parser.parse_args()
    
    # Setup
    setup_logging(args.log_level)
    create_directories()
    
    print("🔍 DNS Tunneling Detection System")
    print("=" * 50)
    
    # Route to appropriate mode
    if args.mode == 'capture':
        run_capture_mode(args.interface, args.pcap)
    elif args.mode == 'analyze':
        run_analysis_mode(args.time_window, args.min_queries)
    elif args.mode == 'train':
        run_training_mode(args.time_window, args.contamination)
    elif args.mode == 'generate':
        run_generate_data_mode(args.legitimate, args.tunneling)
    elif args.mode == 'dashboard':
        run_dashboard_mode()
    else:
        parser.print_help()
        print("\n💡 Quick start:")
        print("1. Generate test data: python main.py generate")
        print("2. Train model: python main.py train")
        print("3. Launch dashboard: python main.py dashboard")

if __name__ == "__main__":
    main()