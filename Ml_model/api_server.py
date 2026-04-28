from flask import Flask, request, jsonify
from anomaly_detector import NetworkAnomalyDetector
from datetime import datetime
import subprocess
import json
import threading
import time

app = Flask(__name__)

# Initialize detector
detector = NetworkAnomalyDetector()

# In-memory storage
recent_anomalies = []
blocked_ips = set()

# Blockchain Configuration
VALIDATOR_ADDRESS = "cosmos1pyhc08t8eytyna8ldzdvyq8sgd53607k0y3syp"
CHAIN_ID = "cybersecurity"

class BlockchainClient:
    def __init__(self, validator_address, chain_id):
        self.validator_address = validator_address
        self.chain_id = chain_id

    def run_command(self, command):
        try:
            result = subprocess.run(
                command,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"Command failed: {e.stderr}")
            return None

    def get_sequence(self):
        cmd = f"cybersecurityd query auth account {self.validator_address} --output json"
        output = self.run_command(cmd)
        if output:
            try:
                data = json.loads(output)
                return int(data.get('account', {}).get('value', {}).get('sequence', 0))
            except Exception as e:
                print(f"Error parsing sequence: {e}")
        return 0

    def submit_anomaly(self, ip, attack_type):
        print(f"🔒 Submitting {ip} ({attack_type}) to blockchain...")
        
        # Get sequence
        seq = self.get_sequence()
        
        # Construct command
        cmd = (
            f"cybersecurityd tx threatintel store-malicious-ip "
            f"--ip-address {ip} "
            f"--from validator "
            f"--keyring-backend test "
            f"--chain-id {self.chain_id} "
            f"--sequence {seq} "
            f"--gas auto "
            f"--gas-adjustment 1.5 "
            f"--gas-prices 0.0001stake "
            f"--yes"
        )

        print(cmd)

        
        output = self.run_command(cmd)
        print(output)
        if output:
            print(f"✅ Blockchain tx submitted for {ip}")
        else:
            print(f"❌ Failed to submit blockchain tx for {ip}")

    def fetch_blocked_ips(self):
        print("🔗 Fetching blocked IPs from blockchain...")
        cmd = "cybersecurityd query threatintel list-malicious-ips --output json"
        output = self.run_command(cmd)
        print(output)
        fetched_ips = set()
        if output:
            try:
                data = json.loads(output)
                # Adjust parsing based on actual response structure
                # The response usually has a key like 'malicious_ips' or similar
                # Based on previous step output, checking structure...
                # We'll try to find the list in the 'MaliciousIp' key which is common for this sdk
                
                # If the output IS the list object directly or inside a wrapper
                # Let's inspect the `list-malicious-ips` output structure dynamically if possible
                # For now assuming standard cosmos-sdk list response: { "maliciousIp": [...] }
                print(data)
                items = data.get('ips', [])
                for item in items:
                    # if 'ipAddress' in item:
                    fetched_ips.add(item)
                        
                print(f"✅ Loaded {len(fetched_ips)} blocked IPs from blockchain.")
                return fetched_ips
            except Exception as e:
                print(f"Error parsing blocked IPs: {e}")
        return set()

blockchain_client = BlockchainClient(VALIDATOR_ADDRESS, CHAIN_ID)

# -------------------------------------------------------
# 🔒 GLOBAL BLOCK ENFORCEMENT
# -------------------------------------------------------
@app.before_request
def check_if_blocked():
    client_ip = request.remote_addr

    if client_ip in blocked_ips:
        return jsonify({
            "error": "Access denied",
            "reason": "IP blocked due to anomaly"
        }), 403


# -------------------------------------------------------
# HEALTH CHECK
# -------------------------------------------------------
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'running',
        'timestamp': datetime.now().isoformat(),
        'service': 'ML Anomaly Detection API'
    })


# -------------------------------------------------------
# ANALYZE FLOW
# -------------------------------------------------------
@app.route('/analyze-flow', methods=['POST'])
def analyze_flow():
    try:
        data = request.json
        if not data or "features" not in data:
            return jsonify({"error": "Missing features"}), 400

        features = data.get('features', {})

        # Run anomaly detection
        result = detector.detect_anomaly(features)

        src_ip = features.get('IPV4_SRC_ADDR', request.remote_addr)

        response = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': features.get('IPV4_DST_ADDR'),
            'src_port': features.get('L4_SRC_PORT'),
            'dst_port': features.get('L4_DST_PORT'),
            'anomaly_detected': result['is_anomaly'],
            'anomaly_score': float(result['anomaly_score']),
            'attack_type': result.get('rf_attack_type', 'BENIGN'),
            'recommendation': 'BLOCK' if result['is_anomaly'] else 'ALLOW',
        }

        # 🔥 BLOCK IF ANOMALY
        if result['is_anomaly']:
            blocked_ips.add(src_ip)
            recent_anomalies.append(response)

            if len(recent_anomalies) > 100:
                recent_anomalies.pop(0)

            print(f"\n🚨 Blocking IP {src_ip} due to anomaly!\n")
            
            # Submit to blockchain in background
            attack_type = response['attack_type']
            threading.Thread(
                target=blockchain_client.submit_anomaly,
                args=(src_ip, attack_type)
            ).start()

            return jsonify(response), 403  # Immediately block

        return jsonify(response), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# -------------------------------------------------------
# RECENT ANOMALIES
# -------------------------------------------------------
@app.route('/recent-anomalies', methods=['GET'])
def get_recent_anomalies():
    limit = request.args.get('limit', 10, type=int)
    return jsonify({
        'anomalies': recent_anomalies[-limit:],
        'total_detected': len(recent_anomalies),
        'timestamp': datetime.now().isoformat()
    }), 200


# -------------------------------------------------------
# STATS
# -------------------------------------------------------
@app.route('/stats', methods=['GET'])
def get_stats():
    return jsonify({
        'total_anomalies': len(recent_anomalies),
        'blocked_ips': list(blocked_ips),
        'timestamp': datetime.now().isoformat()
    }), 200


if __name__ == '__main__':
    # Initial Sync
    try:
        initial_blocks = blockchain_client.fetch_blocked_ips()
        print(initial_blocks)
        blocked_ips.update(initial_blocks)
    except Exception as e:
        print(f"⚠️ Failed to fetch initial blocked IPs: {e}")

    print("Starting ML Anomaly Detection API on http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)