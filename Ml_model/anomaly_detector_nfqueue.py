#!/usr/bin/env python3
import os
import joblib
import numpy as np
import pandas as pd
import ipaddress
import json
import threading
import subprocess
import time
from typing import Dict, List, Any

# netfilterqueue + scapy for live packet handling
# scapy for live packet sniffing
# from netfilterqueue import NetfilterQueue (Removed for passive mode)
from scapy.all import IP, Raw
XGBOOST_AVAILABLE = False
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    print("⚠️ Warning: XGBoost not found. Install with: pip install xgboost")
    print("Some classification features will be limited.")
# --- Begin: Your NetworkAnomalyDetector class (paste your class here) ---
# For brevity in this snippet assume the full NetworkAnomalyDetector class
# you provided is available here as NetworkAnomalyDetector.
# Paste the full class code from your earlier message here (without example_usage).
# --- End: NetworkAnomalyDetector ---

# (To keep the reply short, ensure you paste your full class definition above when using this file)

class BlockchainBridge:
    """
    Helper class to interact with the blockchain CLI (/home/ditya/go/bin/cybersecurityd),
    getting sequence numbers, querying whether an IP is malicious, and submitting transactions.
    """

    def __init__(self, validator_address: str = None, chain_id: str = "cybersecurity"):
        self.chain_id = chain_id
        
        if validator_address:
            self.validator_address = validator_address
        else:
            # Auto-detect from CLI
            try:
                # Assuming binary is in the same path as used elsewhere in this class
                bin_path = '/home/dheerizz/go/bin/cybersecurityd' 
                if not os.path.exists(bin_path):
                    # Fallback to system path
                    bin_path = 'cybersecurityd'
                    
                cmd = [bin_path, 'keys', 'show', 'validator', '-a', '--keyring-backend', 'test']
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).strip()
                self.validator_address = out
                print(f"[bridge] Auto-detected validator address: {self.validator_address}")
            except Exception as e:
                print(f"[bridge] Failed to auto-detect validator address: {e}")
                raise RuntimeError("VALIDATOR_ADDRESS not set and could not be auto-detected.")

        self.lock = threading.Lock()  # protect sequence fetch/submit ordering if needed

    def _run_cli(self, args: List[str], timeout: int = 30) -> str:
        """Run a CLI command and return stdout (raises on nonzero exit)."""
        completed = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True)
        if completed.returncode != 0:
            raise RuntimeError(f"Command {' '.join(args)} failed: {completed.stderr.strip()}")
        return completed.stdout

    def get_latest_sequence(self) -> int:
        """Query account and extract sequence number. Defaults to 0 if absent."""
        try:
            out = self._run_cli(['/home/dheerizz/go/bin/cybersecurityd', 'query', 'auth', 'account', self.validator_address, '-o', 'json'])
            data = json.loads(out)
            # Support different SDK versions
            seq = 0
            if isinstance(data, dict):
                # older/newer cosmos SDK shapes:
                # data.account.value.sequence or data.account.sequence
                account = data.get('account') or data
                # account might be {"value": {...}} or have sequence directly
                if isinstance(account, dict) and 'value' in account and isinstance(account['value'], dict):
                    seq_str = account['value'].get('sequence', '0')
                    seq = int(seq_str) if seq_str is not None else 0
                else:
                    seq_str = account.get('sequence', '0')
                    seq = int(seq_str) if seq_str is not None else 0
            return seq
        except Exception as e:
            # If we fail to query, return 0 (best-effort) but log
            print(f"[blockchain] Warning: failed to get latest sequence: {e}; defaulting to 0")
            return 0

    def is_ip_blocked(self, ip: str) -> bool:
        """Query the chain for whether an IP is marked malicious.
           Assumes a query command like `/home/ditya/go/bin/cybersecurityd query threatintel is-malicious <ip> --output json`.
           Returns True if blocked, False otherwise.
        """
        result = subprocess.run(
            ["/home/dheerizz/go/bin/cybersecurityd", "query", "threatintel", "list-malicious-ips", "-o", "json"],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print("Error querying blockchain:", result.stderr)
            return False

        try:
            data = json.loads(result.stdout)
            for entry in data.get("maliciousIps", []):
                if entry.get("ip") == ip:
                    return True
        except Exception as e:
            print("JSON parse error:", e)
        return False


    def submit_malicious_ip(self, ip: str, attack_type: str = "unknown"):
        """Submit an IP to the chain. Uses sequence fetched dynamically like your Node script.
           This runs the CLI in a thread (caller may spawn a thread).
        """
        try:
            # Acquire lock while fetching seq to avoid race conditions if multiple threads submit
            with self.lock:
                seq = self.get_latest_sequence()
                seq_arg = str(seq)
            cmd = [
                '/home/dheerizz/go/bin/cybersecurityd', 'tx', 'threatintel', 'store-malicious-ip',
                '--ip-address', ip,
                '--from', 'validator',
                '--keyring-backend', 'test',
                '--chain-id', self.chain_id,
                '--sequence', seq_arg,
                '--gas', 'auto',
                '--gas-adjustment', '1.5',
                '--yes',
                '--output', 'json'
            ]
            print(f"[blockchain] Submitting {ip} (attack: {attack_type}) using sequence {seq_arg} ...")
            completed = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if completed.returncode == 0:
                print(f"[blockchain] Successfully submitted {ip}: {completed.stdout.strip()}")
            else:
                print(f"[blockchain] Failed to submit {ip} (exit {completed.returncode}): {completed.stderr.strip()}")
        except Exception as e:
            print(f"[blockchain] Exception while submitting {ip}: {e}")



class NetworkAnomalyDetector:
    """A class for detecting anomalies in network traffic using trained ML models."""

    def __init__(self, model_dir: str = None):
        """Initialize the anomaly detector with trained models.

        Args:
            model_dir: Directory containing the trained models. If None, uses default paths.
        """
        self.base_dir = os.path.dirname(os.path.abspath(__file__))

        # Set default model directories if not provided
        if model_dir is None:
            self.isolation_forest_dir = os.path.join(self.base_dir, 'model')
            self.classifier_dir = os.path.join(self.base_dir, 'models')
        else:
            self.isolation_forest_dir = model_dir
            self.classifier_dir = model_dir

        # Load models
        self.load_models()

        # Define required features - these are the features the scaler expects
        self.required_features = [
            'IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'FLOW_DURATION_MILLISECONDS',
            'LONGEST_FLOW_PKT', 'SHORTEST_FLOW_PKT', 'MIN_IP_PKT_LEN', 'MAX_IP_PKT_LEN',
            'SRC_TO_DST_SECOND_BYTES', 'DST_TO_SRC_SECOND_BYTES', 'SRC_TO_DST_AVG_THROUGHPUT',
            'DST_TO_SRC_AVG_THROUGHPUT', 'RETRANSMITTED_IN_BYTES', 'RETRANSMITTED_OUT_BYTES',
            'RETRANSMITTED_IN_PKTS', 'RETRANSMITTED_OUT_PKTS', 'SRC_TO_DST_IAT_MIN',
            'SRC_TO_DST_IAT_MAX', 'SRC_TO_DST_IAT_AVG', 'SRC_TO_DST_IAT_STDDEV',
            'DST_TO_SRC_IAT_MIN', 'DST_TO_SRC_IAT_MAX', 'DST_TO_SRC_IAT_AVG',
            'DST_TO_SRC_IAT_STDDEV'
        ]

        # Additional features that might be in the packet data but not used by the model
        self.additional_features = [
            'FLOW_START_MILLISECONDS', 'FLOW_END_MILLISECONDS', 'L4_SRC_PORT', 'L4_DST_PORT',
            'PROTOCOL', 'L7_PROTO', 'TCP_FLAGS', 'CLIENT_TCP_FLAGS', 'SERVER_TCP_FLAGS',
            'DURATION_IN', 'DURATION_OUT', 'MIN_TTL', 'MAX_TTL', 'TCP_WIN_MAX_IN',
            'TCP_WIN_MAX_OUT', 'ICMP_TYPE', 'ICMP_IPV4_TYPE', 'DNS_QUERY_ID',
            'DNS_QUERY_TYPE', 'DNS_TTL_ANSWER', 'FTP_COMMAND_RET_CODE',
            'NUM_PKTS_UP_TO_128_BYTES', 'NUM_PKTS_128_TO_256_BYTES',
            'NUM_PKTS_256_TO_512_BYTES', 'NUM_PKTS_512_TO_1024_BYTES', 'NUM_PKTS_1024_TO_1514_BYTES'
        ]

        # IP address features that need to be converted
        self.ip_features = ['IPV4_SRC_ADDR', 'IPV4_DST_ADDR']

    def load_models(self):
        """Load all trained models and scalers."""
        try:
            # Load Isolation Forest model and scaler
            self.isolation_forest = joblib.load(os.path.join(self.isolation_forest_dir, 'isolation_forest_model.pkl'))
            self.scaler = joblib.load(os.path.join(self.isolation_forest_dir, 'scaler.pkl'))
            print("Loaded Isolation Forest model and scaler successfully.")

            # Get the feature names from the scaler if available
            if hasattr(self.scaler, 'feature_names_in_'):
                self.scaler_feature_names = self.scaler.feature_names_in_.tolist()
                print(f"Scaler expects {len(self.scaler_feature_names)} features.")
            else:
                self.scaler_feature_names = self.required_features
                print("Warning: Scaler does not have feature_names_in_ attribute. Using default features.")

            # Initialize classifier flags
            self.has_rf_models = False
            self.has_xgb_models = False
            self.has_classifiers = False

            # Try to load additional models if available
            try:
                # Load Random Forest models
                self.rf_binary_model = joblib.load(os.path.join(self.classifier_dir, 'rf_binary_model.pkl'))
                self.rf_multiclass_model = joblib.load(os.path.join(self.classifier_dir, 'rf_multiclass_model.pkl'))
                self.has_rf_models = True
                print("Loaded Random Forest models successfully.")

                # Load XGBoost models if the library is available
                if XGBOOST_AVAILABLE:
                    try:
                        self.xgb_binary_model = joblib.load(os.path.join(self.classifier_dir, 'xgb_binary_model.pkl'))
                        self.xgb_multiclass_model = joblib.load(os.path.join(self.classifier_dir, 'xgb_multiclass_model.pkl'))
                        self.has_xgb_models = True
                        print("Loaded XGBoost models successfully.")
                    except (FileNotFoundError, OSError) as e:
                        print(f"XGBoost models not found or could not be loaded: {e}")
                else:
                    print("XGBoost models skipped: XGBoost library not available.")

                # Load preprocessing objects
                self.attack_label_encoder = joblib.load(os.path.join(self.classifier_dir, 'attack_label_encoder.pkl'))
                self.feature_names = joblib.load(os.path.join(self.classifier_dir, 'feature_names_list.pkl'))
                self.standard_scaler = joblib.load(os.path.join(self.classifier_dir, 'standard_scaler_fitted.pkl'))

                # Set classifier flag if at least one classifier type is available
                self.has_classifiers = self.has_rf_models or self.has_xgb_models
                if self.has_classifiers:
                    print("Loaded preprocessing objects successfully.")

            except (FileNotFoundError, OSError) as e:
                print(f"Additional classifiers not found or could not be loaded: {e}")
                self.has_classifiers = False

        except (FileNotFoundError, OSError) as e:
            raise RuntimeError(f"Failed to load models: {e}")
        except Exception as e:
            print(f"Warning: Encountered an error during model loading: {e}")
            print("Continuing with limited functionality.")
            self.has_classifiers = False

    def ip_to_int(self, ip: str) -> int:
        """Convert an IP address to an integer representation.

        Args:
            ip: IP address string

        Returns:
            Integer representation of the IP address
        """
        try:
            return int(ipaddress.IPv4Address(ip))
        except ipaddress.AddressValueError:
            return 0

    def preprocess_packet(self, packet_data: Dict) -> pd.DataFrame:

        # Create a DataFrame with a single row
        df = pd.DataFrame([packet_data])

        # Process IP addresses if present
        for ip_feat in self.ip_features:
            if ip_feat in df.columns:
                # Convert IP to integer
                int_col = f"{ip_feat.replace('IPV4_', '')}_INT"
                df[int_col] = df[ip_feat].apply(self.ip_to_int)

                # Extract Class A network
                class_col = f"{ip_feat.replace('IPV4_', '')}_CLASS_A"
                df[class_col] = df[ip_feat].apply(lambda x: int(x.split('.')[0]) if isinstance(x, str) else 0)
            else:
                # If IP features are missing, add placeholder columns
                int_col = f"{ip_feat.replace('IPV4_', '')}_INT"
                class_col = f"{ip_feat.replace('IPV4_', '')}_CLASS_A"
                df[int_col] = 0
                df[class_col] = 0

        # Drop original IP columns if present
        for ip_feat in self.ip_features:
            if ip_feat in df.columns:
                df = df.drop(columns=[ip_feat])

        # Handle missing values
        df = df.fillna(0)

        # Handle infinite values
        df = df.replace([np.inf, -np.inf], [1e10, -1e10])

        # Ensure scaler_feature_names exists (fallback to required_features)
        if not hasattr(self, 'scaler_feature_names') or not self.scaler_feature_names:
            # defensive fallback
            self.scaler_feature_names = getattr(self, 'required_features', list(df.columns))

        # Create a new DataFrame with only the features required by the scaler
        features_df = pd.DataFrame(columns=self.scaler_feature_names)

        # Fill in the values from the original DataFrame
        for feature in self.scaler_feature_names:
            if feature in df.columns:
                features_df[feature] = df[feature]
            else:
                # create column with zero if it was not present
                features_df[feature] = 0

        # Make sure index aligns correctly (single-row)
        features_df = features_df.reset_index(drop=True)

        return features_df

    def scale_features(self, df: pd.DataFrame) -> np.ndarray:
        """Scale features using the pre-trained scaler.

        Args:
            df: DataFrame with features to scale

        Returns:
            Scaled feature array
        """
        if not hasattr(self, 'scaler') or self.scaler is None:
            raise RuntimeError("Scaler not loaded. Install scikit-learn and ensure scaler.pkl exists in the model directory.")

        try:
            # double-check column order expected by scaler
            if hasattr(self.scaler, 'feature_names_in_'):
                expected = list(self.scaler.feature_names_in_)
            else:
                expected = getattr(self, 'scaler_feature_names', list(df.columns))

            # Debugging output when features mismatch
            provided = df.columns.tolist()
            if provided != expected:
                print(f"[debug] Provided features differ from expected scaler features.")
                print(f"[debug] Expected ({len(expected)}): {expected[:10]}{'...' if len(expected)>10 else ''}")
                print(f"[debug] Provided ({len(provided)}): {provided[:10]}{'...' if len(provided)>10 else ''}")

            return self.scaler.transform(df)
        except Exception as e:
            print(f"Error during feature scaling: {e}")
            print(f"Expected features: {getattr(self, 'scaler_feature_names', None)}")
            print(f"Provided features: {df.columns.tolist()}")
            raise

    def detect_anomaly(self, packet_data: Dict) -> Dict:
        """Detect if a network packet is anomalous.

        Args:
            packet_data: Dictionary containing packet features

        Returns:
            Dictionary with detection results
        """
        # Preprocess the packet data
        df = self.preprocess_packet(packet_data)

        # Scale the features
        X_scaled = self.scale_features(df)

        # Make prediction with Isolation Forest
        iso_pred = self.isolation_forest.predict(X_scaled)
        iso_score = self.isolation_forest.score_samples(X_scaled)[0]

        # Convert prediction (-1 = anomaly, 1 = normal) to (1 = anomaly, 0 = normal)
        is_anomaly = 1 if iso_pred[0] == -1 else 0

        result = {
            'is_anomaly': bool(is_anomaly),
            'anomaly_score': float(iso_score),
            'detection_model': 'isolation_forest'
        }

        # If we have classifiers, add more detailed predictions
        if self.has_classifiers:
            try:
                # Prepare features for classifiers if needed
                if hasattr(self, 'feature_names') and self.feature_names:
                    # Create a new DataFrame with classifier features
                    classifier_df = pd.DataFrame(columns=self.feature_names)

                    # Fill in values from original data
                    for feat in self.feature_names:
                        if feat in packet_data:
                            classifier_df[feat] = [packet_data[feat]]
                        else:
                            classifier_df[feat] = 0

                    X_clf_scaled = self.standard_scaler.transform(classifier_df)
                else:
                    X_clf_scaled = X_scaled

                # Add Random Forest predictions if available
                if self.has_rf_models:
                    # Binary classification (benign vs attack)
                    rf_binary_pred = self.rf_binary_model.predict(X_clf_scaled)[0]

                    # Multi-class classification (attack type)
                    rf_attack_type = self.rf_multiclass_model.predict(X_clf_scaled)[0]

                    # Decode attack type
                    if hasattr(self, 'attack_label_encoder'):
                        rf_attack_name = self.attack_label_encoder.inverse_transform([rf_attack_type])[0]
                    else:
                        rf_attack_name = str(rf_attack_type)

                    # Add to results
                    result.update({
                        'rf_binary_prediction': bool(rf_binary_pred),
                        'rf_attack_type': rf_attack_name
                    })

                # Add XGBoost predictions if available
                if self.has_xgb_models:
                    # Binary classification (benign vs attack)
                    xgb_binary_pred = self.xgb_binary_model.predict(X_clf_scaled)[0]

                    # Multi-class classification (attack type)
                    xgb_attack_type = self.xgb_multiclass_model.predict(X_clf_scaled)[0]

                    # Decode attack type
                    if hasattr(self, 'attack_label_encoder'):
                        xgb_attack_name = self.attack_label_encoder.inverse_transform([xgb_attack_type])[0]
                    else:
                        xgb_attack_name = str(xgb_attack_type)

                    # Add to results
                    result.update({
                        'xgb_binary_prediction': bool(xgb_binary_pred),
                        'xgb_attack_type': xgb_attack_name
                    })

                # Add ensemble prediction if both models are available
                if self.has_rf_models and self.has_xgb_models:
                    result['ensemble_prediction'] = bool(is_anomaly or rf_binary_pred or xgb_binary_pred)
                elif self.has_rf_models:
                    result['ensemble_prediction'] = bool(is_anomaly or rf_binary_pred)
                elif self.has_xgb_models:
                    result['ensemble_prediction'] = bool(is_anomaly or xgb_binary_pred)

            except Exception as e:
                print(f"Error in classifier prediction: {e}")
                # Fall back to isolation forest only
                pass

        return result

    def analyze_packet_batch(self, packets: List[Dict]) -> List[Dict]:
        """Analyze a batch of network packets for anomalies.

        Args:
            packets: List of dictionaries, each containing packet features

        Returns:
            List of dictionaries with detection results for each packet
        """
        results = []
        for packet in packets:
            result = self.detect_anomaly(packet)
            # Add original packet info to result
            result['packet'] = packet
            results.append(result)
        return results


class LivePacketHandler:
    def __init__(self, detector: Any, bridge: BlockchainBridge, interface: str = "eth0"):
        self.detector = detector
        self.bridge = bridge
        self.interface = interface
        self.submitted_ips = set()   # in-memory cache

    def _packet_to_minimal_features(self, pkt) -> Dict:
        """
        Build a minimal packet->feature dict expected by the detector.
        """
        features = {}
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            
            features.update({
                'IPV4_SRC_ADDR': src,
                'IPV4_DST_ADDR': dst,
                'IN_BYTES': len(pkt),
                'OUT_BYTES': 0,
                'IN_PKTS': 1,
                'OUT_PKTS': 0,
                'FLOW_DURATION_MILLISECONDS': 0,
                'LONGEST_FLOW_PKT': len(pkt),
                'SHORTEST_FLOW_PKT': len(pkt),
            })
        return features

    def _get_consensus_attack_type(self, result: Dict) -> str:
        """
        Determine the attack type using ensemble voting logic.
        """
        rf_type = result.get('rf_attack_type', '').lower()
        xgb_type = result.get('xgb_attack_type', '').lower()

        if rf_type == xgb_type:
            return result.get('rf_attack_type') or result.get('xgb_attack_type') or 'unknown'

        if rf_type == 'benign' and xgb_type and xgb_type != 'benign':
            return result.get('xgb_attack_type')

        if xgb_type == 'benign' and rf_type and rf_type != 'benign':
            return result.get('rf_attack_type')

        if xgb_type and xgb_type != 'benign':
            return result.get('xgb_attack_type')

        if rf_type and rf_type != 'benign':
            return result.get('rf_attack_type')

        return result.get('detection_model') or 'unknown'

    def _handle(self, packet):
        """Callback invoked by Scapy for each sniffed packet."""
        try:
            if IP not in packet:
                return

            src_ip = packet[IP].src

            # 1) Build minimal feature dict
            pkt_features = self._packet_to_minimal_features(packet)

            # 2) Run detection
            result = self.detector.detect_anomaly(pkt_features)

            if result.get('is_anomaly', False):
                rf_type = result.get('rf_attack_type', '').lower()
                xgb_type = result.get('xgb_attack_type', '').lower()
                
                # If classifiers say benign, ignore
                if rf_type == 'benign' and xgb_type == 'benign':
                    return
                
                # Consensus logic
                attack_type = self._get_consensus_attack_type(result)

                if attack_type.lower() == 'benign':
                    return

                # Log and Submit
                print(f"[detector] ALERT: Attack detected from {src_ip}: Type={attack_type}")

                if src_ip not in self.submitted_ips:
                    self.submitted_ips.add(src_ip)
                    if self.bridge.is_ip_blocked(src_ip):
                        print(f"[detector] IP {src_ip} is ALREADY blocked on-chain.")
                    else:
                        print(f"[detector] Submitting {src_ip} to blockchain...")
                        t = threading.Thread(target=self.bridge.submit_malicious_ip, args=(src_ip, attack_type), daemon=True)
                        t.start()
                else:
                    # Already locally seen
                    pass

        except Exception as e:
            print(f"[sniffer] Error processing packet: {e}")

    def run(self):
        """Start sniffing packets."""
        print(f"[sniffer] Starting Passive Anomaly Detector on {self.interface}...")
        print("[sniffer] Note: This mode detects and reports attacks but DOES NOT block them (Passive Mode).")
        try:
            # Sniff IP packets only, pass to callback
            from scapy.all import sniff
            sniff(iface=self.interface, prn=self._handle, filter="ip", store=0)
        except KeyboardInterrupt:
            print("[sniffer] Stopping...")
        except Exception as e:
            print(f"[sniffer] Critical error: {e}")


def main():
    # Initialize detector (assumes your .pkl models are in expected paths)
    detector = NetworkAnomalyDetector()   # Uses model_dir defaults or pass a path

    # Initialize blockchain bridge
    # Passing None to trigger auto-detection from 'cybersecurityd keys show validator'
    bridge = BlockchainBridge(validator_address=None)

    # Create live handler and run (Passive Mode)
    # Note: eth0 is the default WSL interface usually; change if needed
    handler = LivePacketHandler(detector=detector, bridge=bridge, interface="eth0")
    handler.run()


if __name__ == "__main__":
    main()
