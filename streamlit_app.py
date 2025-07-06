# streamlit_app.py - Streamlit Frontend for Phishing Detection System

import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import time
import base64
from io import BytesIO
import numpy as np

# Page config
st.set_page_config(
    page_title="Phishing Detection System - NCIIPC Challenge",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .threat-high {
        background-color: #ffebee;
        border: 2px solid #f44336;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    .threat-medium {
        background-color: #fff3e0;
        border: 2px solid #ff9800;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    .threat-low {
        background-color: #f3e5f5;
        border: 2px solid #9c27b0;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    .threat-safe {
        background-color: #e8f5e8;
        border: 2px solid #4caf50;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Configuration
import os
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
# API_BASE_URL = "http://localhost:8000"

# Initialize session state
if 'detection_history' not in st.session_state:
    st.session_state.detection_history = []

if 'api_connected' not in st.session_state:
    st.session_state.api_connected = False

# Functions
def check_api_connection():
    """Check if API is accessible"""
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        return response.status_code == 200
    except:
        return False

def detect_single_url(url, organization=None):
    """Detect phishing for a single URL"""
    try:
        payload = {
            "url": url,
            "organization": organization,
            "check_content": True,
            "check_visual": True
        }
        
        response = requests.post(
            f"{API_BASE_URL}/api/v1/detect/url",
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"API Error: {response.status_code}"}
            
    except Exception as e:
        return {"error": str(e)}

def detect_batch_urls(urls, organization=None):
    """Detect phishing for multiple URLs"""
    try:
        payload = {
            "urls": urls,
            "organization": organization
        }
        
        response = requests.post(
            f"{API_BASE_URL}/api/v1/detect/batch",
            json=payload,
            timeout=60
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"API Error: {response.status_code}"}
            
    except Exception as e:
        return {"error": str(e)}

def detect_email(subject, body, sender=None):
    """Detect phishing in email content"""
    try:
        payload = {
            "subject": subject,
            "body": body,
            "sender": sender
        }
        
        response = requests.post(
            f"{API_BASE_URL}/api/v1/detect/email",
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"API Error: {response.status_code}"}
            
    except Exception as e:
        return {"error": str(e)}

def get_model_status():
    """Get model status from API"""
    try:
        response = requests.get(f"{API_BASE_URL}/api/v1/models/status", timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"API Error: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def display_threat_result(result):
    """Display threat detection result with proper styling"""
    if "error" in result:
        st.error(f"Error: {result['error']}")
        return
    
    threat_level = result.get('threat_level', 'UNKNOWN')
    confidence = result.get('confidence_score', 0)
    is_phishing = result.get('is_phishing', False)
    
    # Choose appropriate CSS class
    css_class = {
        'HIGH': 'threat-high',
        'MEDIUM': 'threat-medium',
        'LOW': 'threat-low',
        'SAFE': 'threat-safe'
    }.get(threat_level, 'threat-low')
    
    # Display result
    st.markdown(f"""
    <div class="{css_class}">
        <h3>🛡️ Detection Result</h3>
        <p><strong>URL:</strong> {result.get('url', 'N/A')}</p>
        <p><strong>Threat Level:</strong> {threat_level}</p>
        <p><strong>Confidence Score:</strong> {confidence:.2%}</p>
        <p><strong>Is Phishing:</strong> {'⚠️ YES' if is_phishing else '✅ NO'}</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Show analysis details
    if 'analysis_details' in result:
        with st.expander("🔍 Detailed Analysis"):
            analysis = result['analysis_details']
            
            # URL Features
            if 'url_features' in analysis:
                st.subheader("URL Analysis")
                url_features = analysis['url_features']
                feature_names = [
                    'URL Length', 'Domain Length', 'Path Length', 'Dots Count',
                    'Dashes Count', 'Underscores Count', 'Query Count', 'Equals Count',
                    'Ampersand Count', 'Has IP', 'Has HTTPS', 'Has Suspicious Words',
                    'Many Subdomains', 'Domain Has Numbers', 'Double Slashes'
                ]
                
                for i, (name, value) in enumerate(zip(feature_names, url_features)):
                    st.write(f"**{name}:** {value}")
            
            # Content Analysis
            if 'content_analysis' in analysis:
                st.subheader("Content Analysis")
                content = analysis['content_analysis']
                
                if 'suspicious_keywords' in content:
                    st.write(f"**Suspicious Keywords Found:** {len(content['suspicious_keywords'])}")
                    if content['suspicious_keywords']:
                        st.write("Keywords:", ", ".join(content['suspicious_keywords']))
                
                if 'forms_detected' in content:
                    st.write(f"**Forms Detected:** {content['forms_detected']}")
                
                if 'external_links' in content:
                    st.write(f"**External Links:** {content['external_links']}")
            
            # Domain Information
            if 'domain_info' in analysis:
                st.subheader("Domain Information")
                domain = analysis['domain_info']
                
                st.write(f"**SSL Valid:** {'✅ Yes' if domain.get('ssl_valid', False) else '❌ No'}")
                
                if 'dns_records' in domain and domain['dns_records']:
                    st.write("**DNS Records:**")
                    for record in domain['dns_records']:
                        st.write(f"  - {record}")
            
            # Threat Score Breakdown
            if 'threat_score_breakdown' in analysis:
                st.subheader("Threat Score Breakdown")
                breakdown = analysis['threat_score_breakdown']
                
                # Create a pie chart for score breakdown
                labels = ['URL Score', 'Content Score', 'Domain Score']
                values = [
                    breakdown.get('url_score', 0),
                    breakdown.get('content_score', 0),
                    breakdown.get('domain_score', 0)
                ]
                
                fig = px.pie(values=values, names=labels, title="Threat Score Components")
                st.plotly_chart(fig, use_container_width=True)

# Main App
def main():
    # Header
    st.markdown("""
    <div class="main-header">
        <h1 style="color: white; text-align: center; margin: 0;">
            🛡️ Phishing Detection System
        </h1>
        <p style="color: white; text-align: center; margin: 0;">
            AI-Powered Cybersecurity Solution - NCIIPC Startup India Challenge
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Check API connection
    st.session_state.api_connected = check_api_connection()
    
    if not st.session_state.api_connected:
        st.error("⚠️ Cannot connect to API backend. Please ensure the FastAPI server is running on localhost:8000")
        st.info("Run: `python main.py` to start the backend server")
        return
    
    # Sidebar
    st.sidebar.header("🔧 Configuration")
    
    # Organization selection
    organization = st.sidebar.selectbox(
        "Select Organization",
        ["None", "Banking", "E-commerce", "Healthcare", "Government", "Education", "Other"]
    )
    
    if organization == "None":
        organization = None
    
    # Model status
    with st.sidebar.expander("📊 Model Status"):
        status = get_model_status()
        if "error" not in status:
            st.success("✅ Models Loaded")
            st.write(f"BERT Model: {status.get('bert_model', 'N/A')}")
            st.write(f"URL Model: {status.get('url_feature_model', 'N/A')}")
            
            # Performance metrics
            if 'model_performance' in status:
                perf = status['model_performance']
                st.write("**Performance Metrics:**")
                st.write(f"- URL Model: {perf.get('url_model_accuracy', 0):.1%}")
                st.write(f"- BERT Model: {perf.get('bert_model_accuracy', 0):.1%}")
                st.write(f"- Ensemble: {perf.get('ensemble_accuracy', 0):.1%}")
        else:
            st.error("❌ Model Status Error")
    
    # Main content tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🔍 Single URL Detection", 
        "📋 Batch Processing", 
        "📧 Email Analysis",
        "📈 Analytics Dashboard",
        "⚙️ Admin Panel"
    ])
    
    # Tab 1: Single URL Detection
    with tab1:
        st.header("Single URL Detection")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            url_input = st.text_input(
                "Enter URL to analyze:",
                placeholder="https://example.com",
                help="Enter a complete URL starting with http:// or https://"
            )
        
        with col2:
            st.write("")  # Spacer
            detect_button = st.button("🔍 Detect", use_container_width=True)
        
        if detect_button and url_input:
            with st.spinner("Analyzing URL... This may take a few seconds."):
                result = detect_single_url(url_input, organization)
                
                # Add to history
                st.session_state.detection_history.append({
                    'timestamp': datetime.now(),
                    'url': url_input,
                    'result': result,
                    'type': 'single'
                })
                
                display_threat_result(result)
        
        elif detect_button:
            st.warning("Please enter a URL to analyze.")
    
    # Tab 2: Batch Processing
    with tab2:
        st.header("Batch URL Processing")
        
        # File upload
        uploaded_file = st.file_uploader(
            "Upload CSV file with URLs",
            type=['csv'],
            help="CSV file should have a column named 'url' containing the URLs to analyze"
        )
        
        # Manual URL input
        st.subheader("Or enter URLs manually:")
        url_text = st.text_area(
            "Enter URLs (one per line):",
            height=100,
            placeholder="https://example1.com\nhttps://example2.com\nhttps://example3.com"
        )
        
        if st.button("🔍 Process Batch"):
            urls = []
            
            # Process uploaded file
            if uploaded_file is not None:
                try:
                    df = pd.read_csv(uploaded_file)
                    if 'url' in df.columns:
                        urls.extend(df['url'].tolist())
                    else:
                        st.error("CSV file must contain a 'url' column")
                        return
                except Exception as e:
                    st.error(f"Error reading CSV file: {str(e)}")
                    return
            
            # Process manual input
            if url_text.strip():
                manual_urls = [url.strip() for url in url_text.strip().split('\n') if url.strip()]
                urls.extend(manual_urls)
            
            if urls:
                with st.spinner(f"Processing {len(urls)} URLs..."):
                    result = detect_batch_urls(urls, organization)
                    
                    if "error" not in result:
                        # Add to history
                        st.session_state.detection_history.append({
                            'timestamp': datetime.now(),
                            'urls': urls,
                            'result': result,
                            'type': 'batch'
                        })
                        
                        # Display summary
                        st.success(f"✅ Processed {result['total_urls']} URLs")
                        
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Total URLs", result['total_urls'])
                        with col2:
                            st.metric("Phishing Detected", result['phishing_detected'])
                        with col3:
                            safe_count = result['total_urls'] - result['phishing_detected']
                            st.metric("Safe URLs", safe_count)
                        
                        # Results table
                        st.subheader("Detailed Results")
                        results_data = []
                        for res in result['results']:
                            results_data.append({
                                'URL': res['url'],
                                'Threat Level': res['threat_level'],
                                'Confidence': f"{res['confidence_score']:.2%}",
                                'Is Phishing': '⚠️ YES' if res['is_phishing'] else '✅ NO'
                            })
                        
                        results_df = pd.DataFrame(results_data)
                        st.dataframe(results_df, use_container_width=True)
                        
                        # Download results
                        csv = results_df.to_csv(index=False)
                        st.download_button(
                            label="📥 Download Results",
                            data=csv,
                            file_name=f"phishing_detection_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            mime="text/csv"
                        )
                    else:
                        st.error(f"Batch processing failed: {result['error']}")
            else:
                st.warning("Please upload a CSV file or enter URLs manually.")
    
    # Tab 3: Email Analysis
    with tab3:
        st.header("Email Phishing Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            email_subject = st.text_input("Email Subject:", placeholder="Enter email subject")
            email_sender = st.text_input("Sender (optional):", placeholder="sender@example.com")
        
        with col2:
            email_body = st.text_area(
                "Email Body:",
                height=200,
                placeholder="Enter the email content here..."
            )
        
        if st.button("🔍 Analyze Email"):
            if email_subject and email_body:
                with st.spinner("Analyzing email content..."):
                    result = detect_email(email_subject, email_body, email_sender)
                    
                    if "error" not in result:
                        # Add to history
                        st.session_state.detection_history.append({
                            'timestamp': datetime.now(),
                            'email': {'subject': email_subject, 'body': email_body, 'sender': email_sender},
                            'result': result,
                            'type': 'email'
                        })
                        
                        # Display result
                        threat_level = result.get('threat_level', 'UNKNOWN')
                        confidence = result.get('confidence_score', 0)
                        is_phishing = result.get('is_phishing', False)
                        
                        css_class = {
                            'HIGH': 'threat-high',
                            'MEDIUM': 'threat-medium',
                            'LOW': 'threat-low',
                            'SAFE': 'threat-safe'
                        }.get(threat_level, 'threat-low')
                        
                        st.markdown(f"""
                        <div class="{css_class}">
                            <h3>📧 Email Analysis Result</h3>
                            <p><strong>Threat Level:</strong> {threat_level}</p>
                            <p><strong>Confidence Score:</strong> {confidence:.2%}</p>
                            <p><strong>Is Phishing:</strong> {'⚠️ YES' if is_phishing else '✅ NO'}</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        # Show analysis details
                        if 'analysis_details' in result:
                            with st.expander("🔍 Detailed Analysis"):
                                analysis = result['analysis_details']
                                
                                if 'suspicious_keywords' in analysis:
                                    st.write(f"**Suspicious Keywords:** {len(analysis['suspicious_keywords'])}")
                                    if analysis['suspicious_keywords']:
                                        st.write("Keywords:", ", ".join(analysis['suspicious_keywords']))
                                
                                if 'bert_analysis' in analysis:
                                    st.write("**BERT Analysis:**")
                                    st.json(analysis['bert_analysis'])
                    else:
                        st.error(f"Email analysis failed: {result['error']}")
            else:
                st.warning("Please enter both email subject and body.")
    
    # Tab 4: Analytics Dashboard
    with tab4:
        st.header("Analytics Dashboard")
        
        if st.session_state.detection_history:
            # Filter data
            df_data = []
            for entry in st.session_state.detection_history:
                if entry['type'] == 'single':
                    df_data.append({
                        'timestamp': entry['timestamp'],
                        'type': 'Single URL',
                        'threat_level': entry['result'].get('threat_level', 'UNKNOWN'),
                        'confidence': entry['result'].get('confidence_score', 0),
                        'is_phishing': entry['result'].get('is_phishing', False)
                    })
                elif entry['type'] == 'batch':
                    for result in entry['result'].get('results', []):
                        df_data.append({
                            'timestamp': entry['timestamp'],
                            'type': 'Batch Processing',
                            'threat_level': result.get('threat_level', 'UNKNOWN'),
                            'confidence': result.get('confidence_score', 0),
                            'is_phishing': result.get('is_phishing', False)
                        })
                elif entry['type'] == 'email':
                    df_data.append({
                        'timestamp': entry['timestamp'],
                        'type': 'Email Analysis',
                        'threat_level': entry['result'].get('threat_level', 'UNKNOWN'),
                        'confidence': entry['result'].get('confidence_score', 0),
                        'is_phishing': entry['result'].get('is_phishing', False)
                    })
            
            if df_data:
                df = pd.DataFrame(df_data)
                
                # Metrics
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Total Detections", len(df))
                with col2:
                    phishing_count = df['is_phishing'].sum()
                    st.metric("Phishing Detected", phishing_count)
                with col3:
                    safe_count = len(df) - phishing_count
                    st.metric("Safe URLs", safe_count)
                with col4:
                    avg_confidence = df['confidence'].mean()
                    st.metric("Avg Confidence", f"{avg_confidence:.1%}")
                
                # Charts
                col1, col2 = st.columns(2)
                
                with col1:
                    # Threat level distribution
                    threat_counts = df['threat_level'].value_counts()
                    fig_pie = px.pie(
                        values=threat_counts.values,
                        names=threat_counts.index,
                        title="Threat Level Distribution"
                    )
                    st.plotly_chart(fig_pie, use_container_width=True)
                
                with col2:
                    # Detection type distribution
                    type_counts = df['type'].value_counts()
                    fig_bar = px.bar(
                        x=type_counts.index,
                        y=type_counts.values,
                        title="Detection Type Distribution"
                    )
                    st.plotly_chart(fig_bar, use_container_width=True)
                
                # Timeline
                df['hour'] = df['timestamp'].dt.hour
                hourly_counts = df.groupby('hour').size().reset_index(name='count')
                fig_timeline = px.line(
                    hourly_counts,
                    x='hour',
                    y='count',
                    title="Detection Activity Timeline"
                )
                st.plotly_chart(fig_timeline, use_container_width=True)
                
                # Recent detections table
                st.subheader("Recent Detections")
                recent_df = df.sort_values('timestamp', ascending=False).head(10)
                st.dataframe(recent_df, use_container_width=True)
            else:
                st.info("No data available for analytics.")
        else:
            st.info("No detection history available. Start by analyzing some URLs!")
    
    # Tab 5: Admin Panel
    with tab5:
        st.header("Admin Panel")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🔒 Whitelist Management")
            whitelist_urls = st.text_area(
                "Add URLs to whitelist (one per line):",
                height=100,
                placeholder="https://trusted-site1.com\nhttps://trusted-site2.com"
            )
            
            if st.button("Add to Whitelist"):
                if whitelist_urls.strip():
                    urls = [url.strip() for url in whitelist_urls.strip().split('\n') if url.strip()]
                    try:
                        response = requests.post(
                            f"{API_BASE_URL}/api/v1/admin/whitelist",
                            json=urls
                        )
                        if response.status_code == 200:
                            result = response.json()
                            st.success(f"✅ {result['message']}")
                        else:
                            st.error("Failed to update whitelist")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
        
        with col2:
            st.subheader("🚫 Blacklist Management")
            blacklist_urls = st.text_area(
                "Add URLs to blacklist (one per line):",
                height=100,
                placeholder="https://malicious-site1.com\nhttps://malicious-site2.com"
            )
            
            if st.button("Add to Blacklist"):
                if blacklist_urls.strip():
                    urls = [url.strip() for url in blacklist_urls.strip().split('\n') if url.strip()]
                    try:
                        response = requests.post(
                            f"{API_BASE_URL}/api/v1/admin/blacklist",
                            json=urls
                        )
                        if response.status_code == 200:
                            result = response.json()
                            st.success(f"✅ {result['message']}")
                        else:
                            st.error("Failed to update blacklist")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
        
        # System stats
        st.subheader("📊 System Statistics")
        try:
            response = requests.get(f"{API_BASE_URL}/api/v1/admin/stats")
            if response.status_code == 200:
                stats = response.json()
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Whitelist Count", stats.get('whitelist_count', 0))
                with col2:
                    st.metric("Blacklist Count", stats.get('blacklist_count', 0))
                with col3:
                    status = "✅ Operational" if stats.get('system_status') == 'operational' else "❌ Issues"
                    st.metric("System Status", status)
            else:
                st.error("Failed to retrieve system statistics")
        except Exception as e:
            st.error(f"Error retrieving stats: {str(e)}")
        
        # Clear history
        st.subheader("🗑️ Data Management")
        if st.button("Clear Detection History", type="secondary"):
            st.session_state.detection_history = []
            st.success("✅ Detection history cleared!")
    
    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: #666;'>"
        "🛡️ Phishing Detection System - NCIIPC Startup India AI Grand Challenge<br>"
        "Powered by AI/ML - Built with FastAPI & Streamlit"
        "</div>",
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()