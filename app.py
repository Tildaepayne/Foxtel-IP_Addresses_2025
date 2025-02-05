import os
import json
import requests
import socket
import pandas as pd
import pyshark
import pycountry
import plotly.express as px
import plotly.io as pio
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from flask import Flask, render_template, request, redirect, url_for
import statistics

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the uploads folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Geolocation function
def get_geolocation(ip):
    response = requests.get(f'http://ipinfo.io/{ip}/json')
    if response.status_code == 200:
        data = response.json()
        location = data.get('loc', 'N/A')
        country_code = data.get('country', 'N/A')
        country = pycountry.countries.get(alpha_2=country_code).name if country_code != 'N/A' else 'N/A'
        if location != 'N/A':
            latitude, longitude = location.split(',')
            return float(latitude), float(longitude), country
        else:
            return 'N/A', 'N/A', country
    else:
        return 'N/A', 'N/A', 'N/A'

# Domain name lookup function
def get_domain(ip):
    try:
        domain = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        domain = 'N/A'
    return domain


# Comprehensive Analysis of Wireshark
def process_pcap(file_path):
    # Initial Setup:
    # Opens the PCAP file using pyshark
    # Creates dictionaries to store IP data and timing information
    cap = pyshark.FileCapture(file_path)
    ip_count = {}
    previous_packet_time = {}

    for packet in cap:
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            if src_ip not in ip_count:
                ip_count[src_ip] = {}
            if dst_ip not in ip_count[src_ip]:
                ip_count[src_ip][dst_ip] = {
                    'transmissions': 0,
                    'errors': 0,
                    'time_deltas': [],
                    'packet_lengths': []
                }

            ip_count[src_ip][dst_ip]['transmissions'] += 1

            #Assessing Error
            if hasattr(packet, 'tcp'):
                if hasattr(packet.tcp, 'analysis_retransmission') or \
                   hasattr(packet.tcp, 'analysis_fast_retransmission') or \
                   hasattr(packet.tcp, 'analysis_out_of_order') or \
                   hasattr(packet.tcp, 'analysis_duplicate_ack') or \
                   packet.tcp.flags_reset == '1':
                    ip_count[src_ip][dst_ip]['errors'] += 1

            # Calculate time delta
            if dst_ip in previous_packet_time:
                time_delta = float(packet.sniff_timestamp) - previous_packet_time[dst_ip]
                ip_count[src_ip][dst_ip]['time_deltas'].append(time_delta)
            previous_packet_time[dst_ip] = float(packet.sniff_timestamp)

            # Track packet lengths
            packet_length = int(packet.length)
            ip_count[src_ip][dst_ip]['packet_lengths'].append(packet_length)

    # Statistical Processing:
    # Finds the most active source IP
    # Calculates error percentages
    # Computes average time delays
    # Determines standard deviations
    # Measures packet length statistics
    max_transmissions = 0
    main_source_ip = None
    for src_ip, destinations in ip_count.items():
        total_transmissions = sum(dest['transmissions'] for dest in destinations.values())
        if total_transmissions > max_transmissions:
            max_transmissions = total_transmissions
            main_source_ip = src_ip

    if main_source_ip is None:
        return 'No valid source IP found', []
    
    stats = []
    # Geolocation Integration:
    # Gets geographic coordinates for IPs
    # Resolves domain names
    # Maps countries to IP addresses
    for dst_ip, data in ip_count[main_source_ip].items():
        latitude, longitude, country = get_geolocation(dst_ip)
        domain = get_domain(dst_ip)
        if latitude != 'N/A' and longitude != 'N/A':
            error_percentage = (data['errors'] / data['transmissions']) * 100
            if data['time_deltas']:
                avg_time_delta = sum(data['time_deltas']) / len(data['time_deltas'])
                std_dev_time_delta = statistics.stdev(data['time_deltas']) if len(data['time_deltas']) > 1 else 0
            else:
                avg_time_delta = 'N/A'
                std_dev_time_delta = 'N/A'
            
            if data['packet_lengths']:
                avg_packet_length = sum(data['packet_lengths']) / len(data['packet_lengths'])
                std_dev_packet_length = statistics.stdev(data['packet_lengths']) if len(data['packet_lengths']) > 1 else 0
            else:
                avg_packet_length = 'N/A'
                std_dev_packet_length = 'N/A'

            # Data Organization:
            # Compiles all statistics into structured format
            # Rounds numerical values for clean display
            # Prepares data for visualization

            stats.append({
                'domain': domain,
                'ipv4': dst_ip,
                'ipv6': 'N/A',
                'location': f'{latitude},{longitude}',
                'country': country,
                'transmissions': data['transmissions'],
                'error_percentage': round(error_percentage, 2),
                'average_time_delta': round(avg_time_delta, 8) if avg_time_delta != 'N/A' else 'N/A',
                'std_dev_time_delta': round(std_dev_time_delta, 8) if std_dev_time_delta != 'N/A' else 'N/A',
                'average_packet_length': round(avg_packet_length, 8) if avg_packet_length != 'N/A' else 'N/A',
                'std_dev_packet_length': round(std_dev_packet_length, 8) if std_dev_packet_length != 'N/A' else 'N/A',
                'latitude': latitude,
                'longitude': longitude
            })

    return main_source_ip, stats, ip_count



# Function to generate bubble charts
def generate_bubble_charts(data):
    # Create a DataFrame from the data
    df = pd.DataFrame(data)

    # Create a subplot layout with two columns, specifying 'geo' subplot type
    fig = make_subplots(rows=1, cols=2, specs=[[{'type': 'geo'}, {'type': 'geo'}]])

    # First bubble chart using Scattergeo
    fig.add_trace(
        go.Scattergeo(
            lat=df['latitude'],
            lon=df['longitude'],
            marker=dict(
                size=df['transmissions'],
                color=df['error_percentage'],
                colorscale='RdYlGn_r',
                showscale=True,
                colorbar=dict(title='Error %', x=0.45)  # Position the color bar
            ),
            hovertemplate=(
                "Domain: %{text}<br>" +
                "Frequency: %{marker.size}<br>" +
                "Error percentage: %{marker.color:.2f}<br>" +
                "Longitude: %{lon}<br>" +
                "Latitude: %{lat}" +
                "<extra></extra>"
            ),
            text=df['domain'],
            showlegend=False  # Hide legend entry for this trace
        ),
        row=1, col=1
    )

    # Second bubble chart focused on Australia
    fig.add_trace(
        go.Scattergeo(
            lat=df['latitude'],
            lon=df['longitude'],
            marker=dict(
                size=df['transmissions'],
                color=df['error_percentage'],
                colorscale='Bluered',
                showscale=True,
                colorbar=dict(title='Error %', x=1.0)  # Position the color bar
            ),
            hovertemplate=(
                "Domain: %{text}<br>" +
                "Frequency: %{marker.size}<br>" +
                "Error percentage: %{marker.color:.2f}%<br>" +
                "Longitude: %{lon}<br>" +
                "Latitude: %{lat}" +
                "<extra></extra>"
            ),
            text=df['domain'],
            showlegend=False  # Hide legend entry for this trace
        ),
        row=1, col=2
    )

    # Update the layout for the overall figure
    fig.update_layout(
        title_text="IP Transmission and Error Data Comparison",
        template="plotly_dark",
        geo=dict(
            showframe=False,
            showcoastlines=True,
            projection_type='equirectangular'
        ),
        geo2=dict(
            showframe=False,
            showcoastlines=True,
            projection_type='equirectangular',
            center=dict(lat=-25.2744, lon=133.7751),  # Center on Australia
            projection_scale=4.5  # Zoom level
        )
    )

    # Generate the HTML string for the graph
    graph_html = pio.to_html(fig, full_html=False, include_plotlyjs='cdn')
    return graph_html


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('index'))

    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # Update this line to capture all three returned values
        main_source_ip, stats, ip_count = process_pcap(file_path)
        
        if main_source_ip == 'No valid source IP found':
            return render_template('index.html', error='No valid source IP found in the provided file.')
        
        bubble_charts_html = generate_bubble_charts(stats)

        source_ips = list(set(ip_count.keys()))
        destination_ips = list(set(dst_ip for src_ip in ip_count for dst_ip in ip_count[src_ip]))

        return render_template('results.html', 
                           source_ip=main_source_ip, 
                           stats=stats, 
                           chart_html=bubble_charts_html, 
                           filename=file.filename,
                           source_ips=source_ips, 
                           destination_ips=destination_ips)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)