"""
Streamlit Dashboard for DNS Tunneling Detection
Web interface I built to visualize detection results
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import sqlite3
import sys
import os
from datetime import datetime, timedelta
import time

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from src.capture.dns_capture import DNSCapture
from src.features.extractor import DNSFeatureExtractor
from src.detection.detector import DNSTunnelingDetector

# Page configuration
st.set_page_config(
    page_title="DNS Tunneling Detection System",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize components
@st.cache_resource
def init_components():
    """Initialize system components"""
    capture = DNSCapture("data/dns_traffic.db")
    extractor = DNSFeatureExtractor("data/dns_traffic.db")
    detector = DNSTunnelingDetector("models/")
    
    # Try to load existing model
    detector.load_model()
    
    return capture, extractor, detector

def main():
    st.title("🔍 DNS Tunneling Detection System")
    st.markdown("**Transparent Detection of DNS Tunneling Attacks**")
    
    # Initialize components
    capture, extractor, detector = init_components()
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.selectbox(
        "Choose a page",
        ["Live Monitoring", "Traffic Analysis", "Detection Results", "Model Training", "Settings"]
    )
    
    if page == "Live Monitoring":
        show_live_monitoring(capture, extractor, detector)
    elif page == "Traffic Analysis":
        show_traffic_analysis(capture, extractor)
    elif page == "Detection Results":
        show_detection_results(extractor, detector)
    elif page == "Model Training":
        show_model_training(extractor, detector)
    elif page == "Settings":
        show_settings(detector)

def show_live_monitoring(capture, extractor, detector):
    """Live monitoring dashboard"""
    st.header("Live DNS Traffic Monitoring")
    
    col1, col2, col3, col4 = st.columns(4)
    
    # Get recent statistics
    recent_queries = capture.get_recent_queries(1000)
    
    with col1:
        st.metric("Total Queries", len(recent_queries))
    
    with col2:
        unique_domains = len(set(q['query_name'] for q in recent_queries))
        st.metric("Unique Domains", unique_domains)
    
    with col3:
        suspicious_count = 0  # Will be calculated
        st.metric("Suspicious Domains", suspicious_count)
    
    with col4:
        if recent_queries:
            latest_time = max(q['timestamp'] for q in recent_queries)
            time_diff = time.time() - latest_time
            st.metric("Last Activity", f"{time_diff:.0f}s ago")
        else:
            st.metric("Last Activity", "No data")
    
    # Real-time detection
    st.subheader("Recent Suspicious Activity")
    
    if st.button("Analyze Recent Traffic"):
        with st.spinner("Analyzing DNS traffic..."):
            # Extract features for recent domains
            features_list = extractor.extract_batch_features(time_window_hours=1, min_queries=3)
            
            if features_list:
                # Run detection
                results = detector.batch_detect(features_list)
                suspicious_results = [r for r in results if r['is_suspicious']]
                
                if suspicious_results:
                    st.error(f"⚠️ Found {len(suspicious_results)} suspicious domains!")
                    
                    # Display suspicious domains
                    for result in suspicious_results[:5]:  # Show top 5
                        with st.expander(f"🚨 {result['domain']} (Confidence: {result['confidence']:.2f})"):
                            st.write("**Alerts:**")
                            for alert in result['explanation']:
                                st.write(f"• {alert}")
                            
                            # Show key features
                            domain_features = next((f for f in features_list if f['domain'] == result['domain']), {})
                            if domain_features:
                                col1, col2, col3 = st.columns(3)
                                with col1:
                                    st.metric("Domain Entropy", f"{domain_features.get('domain_entropy', 0):.2f}")
                                with col2:
                                    st.metric("Query Count", domain_features.get('query_count', 0))
                                with col3:
                                    st.metric("NXDOMAIN Ratio", f"{domain_features.get('nxdomain_ratio', 0):.2f}")
                else:
                    st.success("✅ No suspicious activity detected in recent traffic")
            else:
                st.info("No domains with sufficient activity found")
    
    # Traffic timeline
    st.subheader("DNS Query Timeline")
    
    if recent_queries:
        # Create timeline chart
        df = pd.DataFrame(recent_queries)
        df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
        
        # Group by 5-minute intervals
        df_grouped = df.groupby(pd.Grouper(key='datetime', freq='5T')).size().reset_index(name='query_count')
        
        fig = px.line(df_grouped, x='datetime', y='query_count', 
                     title="DNS Queries Over Time (5-minute intervals)")
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
        
        # Top domains
        st.subheader("Most Active Domains")
        domain_counts = df['query_name'].value_counts().head(10)
        
        fig = px.bar(x=domain_counts.values, y=domain_counts.index, orientation='h',
                    title="Top 10 Most Queried Domains")
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)

def show_traffic_analysis(capture, extractor):
    """Traffic analysis dashboard"""
    st.header("DNS Traffic Analysis")
    
    # Time range selector
    col1, col2 = st.columns(2)
    with col1:
        hours_back = st.selectbox("Analysis Time Window", [1, 6, 12, 24, 48], index=2)
    with col2:
        min_queries = st.slider("Minimum Queries per Domain", 1, 50, 5)
    
    if st.button("Analyze Traffic"):
        with st.spinner("Extracting features..."):
            features_list = extractor.extract_batch_features(
                time_window_hours=hours_back, 
                min_queries=min_queries
            )
            
            if not features_list:
                st.warning("No domains found with sufficient activity")
                return
            
            df = pd.DataFrame(features_list)
            
            # Overview statistics
            st.subheader("Traffic Overview")
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric("Analyzed Domains", len(df))
            with col2:
                st.metric("Avg Domain Entropy", f"{df['domain_entropy'].mean():.2f}")
            with col3:
                st.metric("Avg Query Rate", f"{df['query_rate'].mean():.1f}/min")
            with col4:
                st.metric("High Entropy Domains", len(df[df['domain_entropy'] > 4.0]))
            
            # Feature distributions
            st.subheader("Feature Distributions")
            
            # Create subplots
            fig = make_subplots(
                rows=2, cols=2,
                subplot_titles=('Domain Entropy', 'Subdomain Length', 'NXDOMAIN Ratio', 'Query Rate')
            )
            
            fig.add_trace(go.Histogram(x=df['domain_entropy'], name='Domain Entropy'), row=1, col=1)
            fig.add_trace(go.Histogram(x=df['max_label_length'], name='Max Label Length'), row=1, col=2)
            fig.add_trace(go.Histogram(x=df['nxdomain_ratio'], name='NXDOMAIN Ratio'), row=2, col=1)
            fig.add_trace(go.Histogram(x=df['query_rate'], name='Query Rate'), row=2, col=2)
            
            fig.update_layout(height=600, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
            
            # Correlation analysis
            st.subheader("Feature Correlations")
            
            # Select numerical columns for correlation
            numerical_cols = df.select_dtypes(include=['float64', 'int64']).columns
            correlation_cols = [col for col in numerical_cols if col not in ['timestamp', 'query_count']]
            
            if len(correlation_cols) > 1:
                corr_matrix = df[correlation_cols].corr()
                
                fig = px.imshow(corr_matrix, 
                               title="Feature Correlation Matrix",
                               color_continuous_scale='RdBu_r')
                fig.update_layout(height=600)
                st.plotly_chart(fig, use_container_width=True)
            
            # Suspicious domains table
            st.subheader("Potentially Suspicious Domains")
            
            # Simple scoring based on multiple factors
            df['suspicion_score'] = (
                (df['domain_entropy'] > 4.0).astype(int) * 0.3 +
                (df['max_label_length'] > 20).astype(int) * 0.2 +
                (df['nxdomain_ratio'] > 0.3).astype(int) * 0.3 +
                (df['query_rate'] > 5).astype(int) * 0.2
            )
            
            suspicious_df = df[df['suspicion_score'] > 0.3].sort_values('suspicion_score', ascending=False)
            
            if not suspicious_df.empty:
                display_cols = ['domain', 'domain_entropy', 'max_label_length', 
                               'nxdomain_ratio', 'query_rate', 'suspicion_score']
                st.dataframe(suspicious_df[display_cols].head(20))
            else:
                st.success("No obviously suspicious domains found")

def show_detection_results(extractor, detector):
    """Detection results dashboard"""
    st.header("Detection Results")
    
    # Analysis controls
    col1, col2, col3 = st.columns(3)
    with col1:
        time_window = st.selectbox("Time Window", [1, 6, 12, 24], index=1)
    with col2:
        min_queries = st.slider("Min Queries", 1, 20, 3)
    with col3:
        confidence_threshold = st.slider("Confidence Threshold", 0.0, 1.0, 0.5)
    
    if st.button("Run Detection Analysis"):
        with st.spinner("Running detection..."):
            # Extract features
            features_list = extractor.extract_batch_features(
                time_window_hours=time_window,
                min_queries=min_queries
            )
            
            if not features_list:
                st.warning("No data available for analysis")
                return
            
            # Run detection
            results = detector.batch_detect(features_list)
            
            # Filter by confidence threshold
            filtered_results = [r for r in results if r['confidence'] >= confidence_threshold]
            suspicious_results = [r for r in filtered_results if r['is_suspicious']]
            
            # Detection statistics
            st.subheader("Detection Summary")
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Analyzed", len(results))
            with col2:
                st.metric("Above Threshold", len(filtered_results))
            with col3:
                st.metric("Flagged as Suspicious", len(suspicious_results))
            with col4:
                detection_rate = len(suspicious_results) / len(results) if results else 0
                st.metric("Detection Rate", f"{detection_rate:.1%}")
            
            # Results visualization
            if results:
                df_results = pd.DataFrame(results)
                
                # Confidence distribution
                st.subheader("Confidence Score Distribution")
                fig = px.histogram(df_results, x='confidence', nbins=20,
                                 title="Distribution of Confidence Scores")
                fig.add_vline(x=confidence_threshold, line_dash="dash", 
                             annotation_text="Threshold")
                st.plotly_chart(fig, use_container_width=True)
                
                # Rule vs ML scores
                st.subheader("Rule-based vs ML Scores")
                fig = px.scatter(df_results, x='rule_score', y='ml_score',
                               color='is_suspicious', 
                               title="Rule Score vs ML Score",
                               hover_data=['domain'])
                st.plotly_chart(fig, use_container_width=True)
            
            # Detailed results
            if suspicious_results:
                st.subheader("Suspicious Domains Detected")
                
                for result in suspicious_results:
                    with st.expander(f"🚨 {result['domain']} (Confidence: {result['confidence']:.2f})"):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.write("**Detection Details:**")
                            st.write(f"Rule Score: {result['rule_score']:.2f}")
                            st.write(f"ML Score: {result['ml_score']:.2f}")
                            st.write(f"ML Anomaly: {result['ml_anomaly']}")
                        
                        with col2:
                            st.write("**Alerts & Explanations:**")
                            for explanation in result['explanation']:
                                st.write(f"• {explanation}")
                        
                        # Get original features for this domain
                        domain_features = next((f for f in features_list 
                                              if f['domain'] == result['domain']), {})
                        
                        if domain_features:
                            st.write("**Key Features:**")
                            feature_cols = st.columns(4)
                            
                            with feature_cols[0]:
                                st.metric("Entropy", f"{domain_features.get('domain_entropy', 0):.2f}")
                            with feature_cols[1]:
                                st.metric("Max Label", domain_features.get('max_label_length', 0))
                            with feature_cols[2]:
                                st.metric("NXDOMAIN", f"{domain_features.get('nxdomain_ratio', 0):.2f}")
                            with feature_cols[3]:
                                st.metric("Query Rate", f"{domain_features.get('query_rate', 0):.1f}")

def show_model_training(extractor, detector):
    """Model training interface"""
    st.header("Model Training")
    
    st.write("Train the anomaly detection model on historical DNS traffic data.")
    
    # Training parameters
    col1, col2 = st.columns(2)
    with col1:
        training_hours = st.selectbox("Training Data Window (hours)", [24, 48, 72, 168], index=1)
        contamination = st.slider("Expected Contamination Rate", 0.01, 0.3, 0.1)
    
    with col2:
        min_queries_training = st.slider("Min Queries for Training", 5, 50, 10)
    
    if st.button("Train Model"):
        with st.spinner("Extracting training features..."):
            # Extract features for training
            training_features = extractor.extract_batch_features(
                time_window_hours=training_hours,
                min_queries=min_queries_training
            )
            
            if len(training_features) < 10:
                st.error("Insufficient training data. Need at least 10 domains.")
                return
            
            st.info(f"Training on {len(training_features)} domains...")
            
            # Train the model
            detector.train_anomaly_detector(training_features, contamination=contamination)
            
            # Save the model
            detector.save_model()
            
            st.success("✅ Model trained and saved successfully!")
            
            # Show training statistics
            st.subheader("Training Statistics")
            
            df_training = pd.DataFrame(training_features)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Training Samples", len(training_features))
            with col2:
                st.metric("Features Used", len(detector.feature_columns) if detector.feature_columns else 0)
            with col3:
                st.metric("Contamination Rate", f"{contamination:.1%}")
            
            # Feature importance (approximate)
            if detector.feature_columns:
                st.subheader("Feature Statistics")
                
                feature_stats = []
                for col in detector.feature_columns:
                    if col in df_training.columns:
                        stats = {
                            'Feature': col,
                            'Mean': df_training[col].mean(),
                            'Std': df_training[col].std(),
                            'Min': df_training[col].min(),
                            'Max': df_training[col].max()
                        }
                        feature_stats.append(stats)
                
                if feature_stats:
                    st.dataframe(pd.DataFrame(feature_stats))
    
    # Model status
    st.subheader("Current Model Status")
    if detector.is_trained:
        st.success("✅ Model is trained and ready")
        if detector.feature_columns:
            st.write(f"**Features used:** {len(detector.feature_columns)}")
            with st.expander("View feature list"):
                st.write(detector.feature_columns)
    else:
        st.warning("⚠️ No trained model available")

def show_settings(detector):
    """Settings and configuration"""
    st.header("Detection Settings")
    
    st.subheader("Rule-based Detection Thresholds")
    
    # Current thresholds
    thresholds = detector.thresholds.copy()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Domain Analysis Thresholds:**")
        thresholds['max_entropy'] = st.slider("Max Domain Entropy", 0.0, 6.0, thresholds['max_entropy'])
        thresholds['max_label_length'] = st.slider("Max Label Length", 10, 100, thresholds['max_label_length'])
        thresholds['max_subdomain_count'] = st.slider("Max Subdomain Count", 1, 20, thresholds['max_subdomain_count'])
        thresholds['min_nxdomain_ratio'] = st.slider("Min NXDOMAIN Ratio", 0.0, 1.0, thresholds['min_nxdomain_ratio'])
    
    with col2:
        st.write("**Traffic Pattern Thresholds:**")
        thresholds['max_query_rate'] = st.slider("Max Query Rate (per min)", 1.0, 50.0, thresholds['max_query_rate'])
        thresholds['min_interval_cv'] = st.slider("Min Interval CV (periodic)", 0.01, 0.5, thresholds['min_interval_cv'])
        thresholds['max_txt_ratio'] = st.slider("Max TXT Record Ratio", 0.0, 1.0, thresholds['max_txt_ratio'])
        thresholds['min_domain_diversity'] = st.slider("Min Domain Diversity", 0.0, 1.0, thresholds['min_domain_diversity'])
    
    if st.button("Update Thresholds"):
        detector.update_thresholds(thresholds)
        st.success("✅ Thresholds updated successfully!")
    
    # System information
    st.subheader("System Information")
    
    col1, col2 = st.columns(2)
    with col1:
        st.write("**Database:**")
        try:
            conn = sqlite3.connect("data/dns_traffic.db")
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM dns_queries")
            query_count = cursor.fetchone()[0]
            conn.close()
            st.write(f"Total DNS queries: {query_count:,}")
        except:
            st.write("Database not accessible")
    
    with col2:
        st.write("**Model Status:**")
        if detector.is_trained:
            st.write("✅ Trained model available")
        else:
            st.write("❌ No trained model")

if __name__ == "__main__":
    main()