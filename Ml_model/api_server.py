from flask import Flask, request, jsonify
from real_time_monitor import RealTimeNetworkMonitor
from anomaly_detector import NetworkAnomalyDetector
import json
from datetime import datetime
import threading

app = Flask(__name__)

# Initialize detector
detector = NetworkAnomalyDetector()

# Store recent anomalies
recent_anomalies = []

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'running',
        'timestamp': datetime.now().isoformat(),
        'service': 'ML Anomaly Detection API'
    })

@app.route('/analyze-flow', methods=['POST'])
def analyze_flow():
    """
    Analyze a network flow for anomalies.

    Expected input:
    {
        "features": {
            "IPV4_SRC_ADDR": "192.168.1.1",
            "IPV4_DST_ADDR": "10.0.0.1",
            ... (all other features from extract_packet_features)
        }
    }
    """
    try:
        data = request.json
        features = data.get('features', {})

        # Run anomaly detection
        result = detector.detect_anomaly(features)

        # Prepare response for blockchain
        response = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': features.get('IPV4_SRC_ADDR'),
            'dst_ip': features.get('IPV4_DST_ADDR'),
            'src_port': features.get('L4_SRC_PORT'),
            'dst_port': features.get('L4_DST_PORT'),
            'anomaly_detected': result['is_anomaly'],
            'anomaly_score': float(result['anomaly_score']),
            'confidence': float(result.get('confidence', 0.0)),
            'attack_type': result.get('rf_attack_type', 'BENIGN'),
            'xgb_attack_type': result.get('xgb_attack_type', 'BENIGN'),
            'recommendation': 'BLOCK' if result['is_anomaly'] else 'ALLOW',
            'packet_size': features.get('IN_BYTES', 0),
            'protocol': features.get('PROTOCOL', 0),
        }

        # Store anomaly if detected
        if result['is_anomaly']:
            recent_anomalies.append(response)
            if len(recent_anomalies) > 100:
                recent_anomalies.pop(0)

        return jsonify(response), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/recent-anomalies', methods=['GET'])
def get_recent_anomalies():
    """Get recently detected anomalies."""
    limit = request.args.get('limit', 10, type=int)
    return jsonify({
        'anomalies': recent_anomalies[-limit:],
        'total_detected': len(recent_anomalies),
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get detection statistics."""
    if not recent_anomalies:
        return jsonify({
            'total_anomalies': 0,
            'anomaly_types': {},
            'last_anomaly': None
        }), 200

    # Count attack types
    attack_counts = {}
    for anomaly in recent_anomalies:
        attack_type = anomaly.get('attack_type', 'BENIGN')
        attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1

    return jsonify({
        'total_anomalies': len(recent_anomalies),
        'anomaly_types': attack_counts,
        'last_anomaly': recent_anomalies[-1] if recent_anomalies else None,
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/inject-dummy-anomaly', methods=['POST'])
def inject_dummy_anomaly():
    """Manually injects a fake malicious anomaly for testing."""
    dummy_anomaly = {
        'timestamp': datetime.now().isoformat(),
        'src_ip': '1.2.3.6',  # A fake malicious IP
        'dst_ip': '192.168.1.100',
        'src_port': 12345,
        'dst_port': 80,
        'anomaly_detected': True,
        'anomaly_score': 0.95,
        'confidence': 0.99,
        'attack_type': 'DDoS', # Important: This is NOT "Benign"
        'recommendation': 'BLOCK',
        'packet_size': 1500,
        'protocol': 6,
    }
    recent_anomalies.append(dummy_anomaly)
    print("\n>>> Dummy DDoS anomaly from 1.2.3.6 injected successfully! <<<\n")
    return jsonify({'status': 'Dummy anomaly injected'}), 200

if __name__ == '__main__':
    print("Starting ML Anomaly Detection API on http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
