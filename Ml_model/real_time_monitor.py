import os
import time
import json
import threading
import sys
import ctypes
from datetime import datetime
from collections import deque, defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP
from anomaly_detector import NetworkAnomalyDetector

class RealTimeNetworkMonitor:
    """Real-time network traffic monitoring and anomaly detection system."""

    def __init__(self, interface=None, log_file='network_anomalies.log'):
        """Initialize the network monitor.

        Args:
            interface: Network interface to monitor (None = all interfaces)
            log_file: File to log detected anomalies
        """
        self.interface = interface
        self.log_file = log_file
        self.detector = NetworkAnomalyDetector()

        # Statistics tracking
        self.stats = {
            'total_packets': 0,
            'anomalies_detected': 0,
            'benign_packets': 0,
            'start_time': time.time()
        }

        # Flow tracking for aggregating packets into flows
        self.flows = defaultdict(lambda: {
            'packets': deque(maxlen=100),
            'start_time': None,
            'last_seen': None,
            'src_bytes': 0,
            'dst_bytes': 0,
            'src_pkts': 0,
            'dst_pkts': 0
        })

        # Recent anomalies (last 100)
        self.recent_anomalies = deque(maxlen=100)

        # Attack type statistics
        self.attack_types = defaultdict(int)

        # Running flag
        self.running = False

        # Lock for thread-safe operations
        self.lock = threading.Lock()

    def get_flow_key(self, packet):
        """Generate a unique key for a network flow."""
        if IP not in packet:
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        src_port = 0
        dst_port = 0

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Create bidirectional flow key (sorted to match both directions)
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, src_port, dst_ip, dst_port, protocol)
        else:
            return (dst_ip, dst_port, src_ip, src_port, protocol)

    def extract_packet_features(self, packet):
        """Extract features from a captured packet for anomaly detection."""
        if IP not in packet:
            return None

        features = {}
        current_time = int(time.time() * 1000)  # milliseconds

        # Basic IP information
        features['IPV4_SRC_ADDR'] = packet[IP].src
        features['IPV4_DST_ADDR'] = packet[IP].dst
        features['PROTOCOL'] = packet[IP].proto

        # Packet size
        pkt_len = len(packet)
        features['MIN_IP_PKT_LEN'] = pkt_len
        features['MAX_IP_PKT_LEN'] = pkt_len
        features['LONGEST_FLOW_PKT'] = pkt_len
        features['SHORTEST_FLOW_PKT'] = pkt_len

        # TTL
        features['MIN_TTL'] = packet[IP].ttl
        features['MAX_TTL'] = packet[IP].ttl

        # Port information
        if TCP in packet:
            features['L4_SRC_PORT'] = packet[TCP].sport
            features['L4_DST_PORT'] = packet[TCP].dport
            features['TCP_FLAGS'] = int(packet[TCP].flags)
            features['CLIENT_TCP_FLAGS'] = int(packet[TCP].flags)
            features['SERVER_TCP_FLAGS'] = 0
            features['TCP_WIN_MAX_IN'] = packet[TCP].window
            features['TCP_WIN_MAX_OUT'] = 0
        elif UDP in packet:
            features['L4_SRC_PORT'] = packet[UDP].sport
            features['L4_DST_PORT'] = packet[UDP].dport
            features['TCP_FLAGS'] = 0
            features['CLIENT_TCP_FLAGS'] = 0
            features['SERVER_TCP_FLAGS'] = 0
            features['TCP_WIN_MAX_IN'] = 0
            features['TCP_WIN_MAX_OUT'] = 0
        else:
            features['L4_SRC_PORT'] = 0
            features['L4_DST_PORT'] = 0
            features['TCP_FLAGS'] = 0
            features['CLIENT_TCP_FLAGS'] = 0
            features['SERVER_TCP_FLAGS'] = 0
            features['TCP_WIN_MAX_IN'] = 0
            features['TCP_WIN_MAX_OUT'] = 0

        # ICMP
        if ICMP in packet:
            features['ICMP_TYPE'] = packet[ICMP].type
            features['ICMP_IPV4_TYPE'] = packet[ICMP].type
        else:
            features['ICMP_TYPE'] = 0
            features['ICMP_IPV4_TYPE'] = 0

        # Flow timing (simplified for single packet)
        features['FLOW_START_MILLISECONDS'] = current_time
        features['FLOW_END_MILLISECONDS'] = current_time
        features['FLOW_DURATION_MILLISECONDS'] = 1
        features['DURATION_IN'] = 0
        features['DURATION_OUT'] = 0

        # Byte and packet counts (for single packet)
        features['IN_BYTES'] = pkt_len
        features['OUT_BYTES'] = 0
        features['IN_PKTS'] = 1
        features['OUT_PKTS'] = 0

        # Throughput (bytes per millisecond)
        features['SRC_TO_DST_SECOND_BYTES'] = pkt_len
        features['DST_TO_SRC_SECOND_BYTES'] = 0
        features['SRC_TO_DST_AVG_THROUGHPUT'] = pkt_len * 1000
        features['DST_TO_SRC_AVG_THROUGHPUT'] = 0

        # Retransmissions
        features['RETRANSMITTED_IN_BYTES'] = 0
        features['RETRANSMITTED_IN_PKTS'] = 0
        features['RETRANSMITTED_OUT_BYTES'] = 0
        features['RETRANSMITTED_OUT_PKTS'] = 0

        # Inter-arrival times (0 for single packet)
        features['SRC_TO_DST_IAT_MIN'] = 0
        features['SRC_TO_DST_IAT_MAX'] = 0
        features['SRC_TO_DST_IAT_AVG'] = 0
        features['SRC_TO_DST_IAT_STDDEV'] = 0
        features['DST_TO_SRC_IAT_MIN'] = 0
        features['DST_TO_SRC_IAT_MAX'] = 0
        features['DST_TO_SRC_IAT_AVG'] = 0
        features['DST_TO_SRC_IAT_STDDEV'] = 0

        # Packet size distribution
        if pkt_len <= 128:
            features['NUM_PKTS_UP_TO_128_BYTES'] = 1
            features['NUM_PKTS_128_TO_256_BYTES'] = 0
            features['NUM_PKTS_256_TO_512_BYTES'] = 0
            features['NUM_PKTS_512_TO_1024_BYTES'] = 0
            features['NUM_PKTS_1024_TO_1514_BYTES'] = 0
        elif pkt_len <= 256:
            features['NUM_PKTS_UP_TO_128_BYTES'] = 0
            features['NUM_PKTS_128_TO_256_BYTES'] = 1
            features['NUM_PKTS_256_TO_512_BYTES'] = 0
            features['NUM_PKTS_512_TO_1024_BYTES'] = 0
            features['NUM_PKTS_1024_TO_1514_BYTES'] = 0
        elif pkt_len <= 512:
            features['NUM_PKTS_UP_TO_128_BYTES'] = 0
            features['NUM_PKTS_128_TO_256_BYTES'] = 0
            features['NUM_PKTS_256_TO_512_BYTES'] = 1
            features['NUM_PKTS_512_TO_1024_BYTES'] = 0
            features['NUM_PKTS_1024_TO_1514_BYTES'] = 0
        elif pkt_len <= 1024:
            features['NUM_PKTS_UP_TO_128_BYTES'] = 0
            features['NUM_PKTS_128_TO_256_BYTES'] = 0
            features['NUM_PKTS_256_TO_512_BYTES'] = 0
            features['NUM_PKTS_512_TO_1024_BYTES'] = 1
            features['NUM_PKTS_1024_TO_1514_BYTES'] = 0
        else:
            features['NUM_PKTS_UP_TO_128_BYTES'] = 0
            features['NUM_PKTS_128_TO_256_BYTES'] = 0
            features['NUM_PKTS_256_TO_512_BYTES'] = 0
            features['NUM_PKTS_512_TO_1024_BYTES'] = 0
            features['NUM_PKTS_1024_TO_1514_BYTES'] = 1

        # Protocol identification (simplified)
        features['L7_PROTO'] = 0
        features['DNS_QUERY_ID'] = 0
        features['DNS_QUERY_TYPE'] = 0
        features['DNS_TTL_ANSWER'] = 0
        features['FTP_COMMAND_RET_CODE'] = 0

        # Identify common protocols by port
        dst_port = features['L4_DST_PORT']
        if dst_port == 53:
            features['L7_PROTO'] = 5.0  # DNS
        elif dst_port == 80:
            features['L7_PROTO'] = 7.0  # HTTP
        elif dst_port == 443:
            features['L7_PROTO'] = 91.0  # HTTPS
        elif dst_port == 21:
            features['L7_PROTO'] = 1.0  # FTP
        elif dst_port == 22:
            features['L7_PROTO'] = 92.0  # SSH

        return features

    def packet_handler(self, packet):
        """Handle each captured packet."""
        try:
            # Extract features
            features = self.extract_packet_features(packet)
            if features is None:
                return

            # Update statistics
            with self.lock:
                self.stats['total_packets'] += 1

            # Detect anomaly
            result = self.detector.detect_anomaly(features)

            # Update statistics and log if anomaly detected
            if result['is_anomaly']:
                with self.lock:
                    self.stats['anomalies_detected'] += 1

                    # Track attack types if available
                    if 'rf_attack_type' in result:
                        self.attack_types[result['rf_attack_type']] += 1

                    # Add to recent anomalies
                    anomaly_info = {
                        'timestamp': datetime.now().isoformat(),
                        'src_ip': features['IPV4_SRC_ADDR'],
                        'dst_ip': features['IPV4_DST_ADDR'],
                        'src_port': features['L4_SRC_PORT'],
                        'dst_port': features['L4_DST_PORT'],
                        'protocol': features['PROTOCOL'],
                        'anomaly_score': result['anomaly_score'],
                        'packet_size': features['IN_BYTES']
                    }

                    # Add attack type if available
                    if 'rf_attack_type' in result:
                        anomaly_info['attack_type'] = result['rf_attack_type']
                    if 'xgb_attack_type' in result:
                        anomaly_info['xgb_attack_type'] = result['xgb_attack_type']

                    self.recent_anomalies.append(anomaly_info)

                    # Log to file
                    self.log_anomaly(anomaly_info)

                    # Print alert
                    self.print_alert(anomaly_info)
            else:
                with self.lock:
                    self.stats['benign_packets'] += 1

        except Exception as e:
            print(f"Error processing packet: {e}")

    def log_anomaly(self, anomaly_info):
        """Log anomaly to file."""
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(anomaly_info) + '\n')
        except Exception as e:
            print(f"Error logging anomaly: {e}")

    def print_alert(self, anomaly_info):
        """Print anomaly alert to console."""
        print("\n" + "="*80)
        print("🚨 ANOMALY DETECTED!")
        print("="*80)
        print(f"Time: {anomaly_info['timestamp']}")
        print(f"Source: {anomaly_info['src_ip']}:{anomaly_info['src_port']}")
        print(f"Destination: {anomaly_info['dst_ip']}:{anomaly_info['dst_port']}")
        print(f"Protocol: {anomaly_info['protocol']}")
        print(f"Anomaly Score: {anomaly_info['anomaly_score']:.6f}")
        print(f"Packet Size: {anomaly_info['packet_size']} bytes")

        if 'attack_type' in anomaly_info:
            print(f"Attack Type (RF): {anomaly_info['attack_type']}")
        if 'xgb_attack_type' in anomaly_info:
            print(f"Attack Type (XGB): {anomaly_info['xgb_attack_type']}")

        print("="*80 + "\n")

    def print_statistics(self):
        """Print monitoring statistics."""
        with self.lock:
            runtime = time.time() - self.stats['start_time']

            print("\n" + "="*80)
            print("📊 NETWORK MONITORING STATISTICS")
            print("="*80)
            print(f"Runtime: {runtime:.2f} seconds")
            print(f"Total Packets: {self.stats['total_packets']}")
            print(f"Anomalies Detected: {self.stats['anomalies_detected']}")
            print(f"Benign Packets: {self.stats['benign_packets']}")

            if self.stats['total_packets'] > 0:
                anomaly_rate = (self.stats['anomalies_detected'] / self.stats['total_packets']) * 100
                print(f"Anomaly Rate: {anomaly_rate:.2f}%")

            print(f"Packets/Second: {self.stats['total_packets'] / runtime:.2f}")

            if self.attack_types:
                print("\nAttack Types Detected:")
                for attack_type, count in sorted(self.attack_types.items(),
                                                key=lambda x: x[1], reverse=True):
                    print(f"  - {attack_type}: {count}")

            print("="*80 + "\n")

    def start_monitoring(self, duration=None, packet_count=None):
        """Start monitoring network traffic.

        Args:
            duration: Optional duration in seconds (None = infinite)
            packet_count: Optional number of packets to capture (None = infinite)
        """
        self.running = True
        self.stats['start_time'] = time.time()

        print("\n🔍 Starting network monitoring...")
        print(f"Interface: {self.interface if self.interface else 'All interfaces'}")
        print(f"Log file: {self.log_file}")

        if duration:
            print(f"Duration: {duration} seconds")
        if packet_count:
            print(f"Packet count: {packet_count}")

        print("\nPress Ctrl+C to stop monitoring\n")

        # Start statistics printer thread
        stats_thread = threading.Thread(target=self.stats_printer, daemon=True)
        stats_thread.start()

        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=False,
                timeout=duration,
                count=packet_count,
                filter="ip"  # Only capture IP packets
            )
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped by user.")
        except Exception as e:
            print(f"\nError during monitoring: {e}")
        finally:
            self.running = False
            self.print_statistics()
            print(f"\nResults saved to: {self.log_file}")

    def stats_printer(self):
        """Periodically print statistics while monitoring."""
        while self.running:
            time.sleep(30)  # Print every 30 seconds
            if self.running:
                self.print_statistics()


def main():
    """Main function to run the network monitor."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Real-time Network Anomaly Detection Monitor'
    )
    parser.add_argument(
        '-i', '--interface',
        help='Network interface to monitor (default: all interfaces)',
        default=None
    )
    parser.add_argument(
        '-d', '--duration',
        type=int,
        help='Monitoring duration in seconds',
        default=None
    )
    parser.add_argument(
        '-c', '--count',
        type=int,
        help='Number of packets to capture',
        default=None
    )
    parser.add_argument(
        '-l', '--log-file',
        help='Log file path',
        default='network_anomalies.log'
    )

    args = parser.parse_args()

    # Check for root/admin privileges
    if os.geteuid() != 0:
        print("⚠️  Warning: This script requires root/administrator privileges to capture packets.")
        print("Please run with sudo: sudo python real_time_monitor.py")
        return

    # Create and start monitor
    monitor = RealTimeNetworkMonitor(
        interface=args.interface,
        log_file=args.log_file
    )

    monitor.start_monitoring(
        duration=args.duration,
        packet_count=args.count
    )


if __name__ == "__main__":
    main()
