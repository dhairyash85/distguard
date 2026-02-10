#!/usr/bin/env python3
import os
import json
import pprint
import time
from anomaly_detector_nfqueue import NetworkAnomalyDetector, BlockchainBridge

def make_packet(low=False):
    """
    Construct a synthetic packet_data dict. If low=False -> high-volume (DoS-like).
    Tune numbers to mimic your real extractor's fields.
    """
    if low:
        return {
            'IPV4_SRC_ADDR': '192.0.2.6',
            'IPV4_DST_ADDR': '198.51.100.10',
            'IN_BYTES': 500,            # small
            'OUT_BYTES': 200,
            'IN_PKTS': 5,
            'OUT_PKTS': 2,
            'FLOW_DURATION_MILLISECONDS': 200,
            'SRC_TO_DST_AVG_THROUGHPUT': 2500,   # bytes/sec
            'DST_TO_SRC_AVG_THROUGHPUT': 1200,
            # other fields defaulted by detector preprocess
        }
    else:
        # "DoS-like" synthetic record
        return {
            'IPV4_SRC_ADDR': '203.0.113.9',
            'IPV4_DST_ADDR': '198.51.100.10',
            'IN_BYTES': 50_000_000,    # 50 MB during the observed flow
            'OUT_BYTES': 1000,
            'IN_PKTS': 50000,
            'OUT_PKTS': 100,
            'FLOW_DURATION_MILLISECONDS': 60_000,  # 1 minute flow
            'SRC_TO_DST_AVG_THROUGHPUT': 800_000,  # bytes/sec (~6.4 Mbps)
            'DST_TO_SRC_AVG_THROUGHPUT': 1_000,
            'LONGEST_FLOW_PKT': 1500,
            'SHORTEST_FLOW_PKT': 64,
            'RETRANSMITTED_IN_BYTES': 0,
            'RETRANSMITTED_IN_PKTS': 0,
            # you can add more features your scaler expects if needed
        }

def get_consensus_attack_type(result):
    """
    Determine the attack type using ensemble voting logic.
    Prioritizes non-benign classifications when models disagree.
    """
    rf_type = result.get('rf_attack_type', '').lower()
    xgb_type = result.get('xgb_attack_type', '').lower()

    # If both models agree, use that classification
    if rf_type == xgb_type:
        return result.get('rf_attack_type') or result.get('xgb_attack_type') or 'unknown'

    # If models disagree and one says benign, trust the non-benign one
    if rf_type == 'benign' and xgb_type and xgb_type != 'benign':
        return result.get('xgb_attack_type')

    if xgb_type == 'benign' and rf_type and rf_type != 'benign':
        return result.get('rf_attack_type')

    # If both are non-benign but different, prefer XGBoost (typically more accurate)
    if xgb_type and xgb_type != 'benign':
        return result.get('xgb_attack_type')

    if rf_type and rf_type != 'benign':
        return result.get('rf_attack_type')

    # Fallback
    return result.get('detection_model') or 'unknown'

def process_and_submit(detector, bridge, packet_data, description):
    """
    Analyze a packet and submit to blockchain if it's malicious.

    Args:
        detector: NetworkAnomalyDetector instance
        bridge: BlockchainBridge instance
        packet_data: Dictionary containing packet features
        description: String description for logging
    """
    pp = pprint.PrettyPrinter(indent=2)

    print(f"\n{'='*60}")
    print(f"=== {description} ===")
    print(f"{'='*60}")

    # Run detection
    result = detector.detect_anomaly(packet_data)

    print("\n[Detection Result]")
    pp.pprint(result)

    # Extract source IP
    src_ip = packet_data.get('IPV4_SRC_ADDR', 'unknown')

    # Check if it's an anomaly
    if result.get('is_anomaly', False):
        # Use consensus logic to determine attack type
        attack_type = get_consensus_attack_type(result)

        # Show individual model predictions
        rf_pred = result.get('rf_attack_type', 'N/A')
        xgb_pred = result.get('xgb_attack_type', 'N/A')

        print(f"\n⚠️  ANOMALY DETECTED from {src_ip}")
        print(f"  Random Forest prediction: {rf_pred}")
        print(f"  XGBoost prediction: {xgb_pred}")
        print(f"  Consensus Attack Type: {attack_type}")

        # Check if consensus is benign
        if attack_type.lower() == 'benign':
            print(f"\n✓ Consensus classification is 'Benign' - IGNORING (not submitting to blockchain)")
        else:
            print(f"\n🔒 Submitting {src_ip} to blockchain...")

            # Check if already blocked
            if bridge.is_ip_blocked(src_ip):
                print(f"⚠️  IP {src_ip} is already blocked on the blockchain")
            else:
                # Submit to blockchain
                try:
                    bridge.submit_malicious_ip(src_ip, attack_type)
                    print(f"✓ Successfully submitted {src_ip} to blockchain")

                    # Wait a moment for transaction to process
                    time.sleep(2)

                    # Verify it's now blocked
                    if bridge.is_ip_blocked(src_ip):
                        print(f"✓ Verified: {src_ip} is now blocked on the blockchain")
                    else:
                        print(f"⚠️  Warning: {src_ip} was submitted but not yet visible on chain (may need more time)")

                except Exception as e:
                    print(f"❌ Error submitting to blockchain: {e}")
    else:
        print(f"\n✓ Normal traffic from {src_ip} - No action needed")

    print(f"\n{'='*60}\n")
    return result

def main():
    print("="*60)
    print("Network Anomaly Detection & Blockchain Integration Test")
    print("="*60)

    # Initialize detector
    print("\n[1] Initializing Network Anomaly Detector...")
    detector = NetworkAnomalyDetector()
    print("✓ Detector initialized")

    # Initialize blockchain bridge
    print("\n[2] Initializing Blockchain Bridge...")
    validator_addr = "cosmos199xtarytzzw3qm0vaz8pkz7ure4w9k94qp53e4"
    bridge = BlockchainBridge(validator_address=validator_addr)
    print("✓ Blockchain bridge initialized")

    # Test 1: Normal traffic (low load)
    normal_packet = make_packet(low=True)
    result_normal = process_and_submit(
        detector,
        bridge,
        normal_packet,
        "Test 1: Normal Traffic (Low Load)"
    )

    # Test 2: DoS-like traffic (high load)
    dos_packet = make_packet(low=False)
    result_dos = process_and_submit(
        detector,
        bridge,
        dos_packet,
        "Test 2: DoS-like Traffic (High Load)"
    )

    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"\nNormal Packet (192.0.2.6):")
    print(f"  - Anomaly: {result_normal.get('is_anomaly', False)}")

    print(f"\nDoS Packet (203.0.113.9):")
    print(f"  - Anomaly: {result_dos.get('is_anomaly', False)}")
    if result_dos.get('is_anomaly', False):
        attack_type = (
            result_dos.get('rf_attack_type') or
            result_dos.get('xgb_attack_type') or
            'unknown'
        )
        print(f"  - Attack Type: {attack_type}")
        print(f"  - Submitted to Blockchain: {attack_type.lower() != 'benign'}")

    # Check final blockchain state
    print(f"\n[Final Blockchain Status]")
    for ip in ['192.0.2.6', '203.0.113.9']:
        is_blocked = bridge.is_ip_blocked(ip)
        status = "🔒 BLOCKED" if is_blocked else "✓ Not Blocked"
        print(f"  {ip}: {status}")

    print("\n" + "="*60)
    print("Test completed!")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
