import os
import joblib
import numpy as np
import pandas as pd
import ipaddress
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple, Union, Optional

# Check for optional dependencies
XGBOOST_AVAILABLE = False
try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    print("⚠️ Warning: XGBoost not found. Install with: pip install xgboost")
    print("Some classification features will be limited.")

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
        """Preprocess a single network packet for anomaly detection.

        Args:
            packet_data: Dictionary containing packet features

        Returns:
            Preprocessed DataFrame ready for model input
        """
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

        # Create a new DataFrame with only the features required by the scaler
        # This ensures the feature order matches what the scaler expects
        features_df = pd.DataFrame(columns=self.scaler_feature_names)

        # Fill in the values from the original DataFrame
        for feature in self.scaler_feature_names:
            if feature in df.columns:
                features_df[feature] = df[feature]
            else:
                features_df[feature] = 0

        return features_df

    def scale_features(self, df: pd.DataFrame) -> np.ndarray:
        """Scale features using the pre-trained scaler.

        Args:
            df: DataFrame with features to scale

        Returns:
            Scaled feature array
        """
        try:
            return self.scaler.transform(df)
        except Exception as e:
            print(f"Error during feature scaling: {e}")
            print(f"Expected features: {self.scaler_feature_names}")
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


# Example usage function
def example_usage():
    """Example of how to use the NetworkAnomalyDetector class."""
    # Create detector instance
    detector = NetworkAnomalyDetector()

    # Example packet data (this should be replaced with actual packet capture)
    example_packet = {
        'FLOW_START_MILLISECONDS': 1424242193040,
        'FLOW_END_MILLISECONDS': 1424242193043,
        'IPV4_SRC_ADDR': '59.166.0.2',
        'L4_SRC_PORT': 4894,
        'IPV4_DST_ADDR': '149.171.126.3',
        'L4_DST_PORT': 53,
        'PROTOCOL': 17,
        'L7_PROTO': 5.0,
        'IN_BYTES': 146,
        'IN_PKTS': 2,
        'OUT_BYTES': 178,
        'OUT_PKTS': 2,
        'TCP_FLAGS': 0,
        'CLIENT_TCP_FLAGS': 0,
        'SERVER_TCP_FLAGS': 0,
        'FLOW_DURATION_MILLISECONDS': 2,
        'DURATION_IN': 0,
        'DURATION_OUT': 0,
        'MIN_TTL': 31,
        'MAX_TTL': 31,
        'LONGEST_FLOW_PKT': 89,
        'SHORTEST_FLOW_PKT': 73,
        'MIN_IP_PKT_LEN': 73,
        'MAX_IP_PKT_LEN': 89,
        'SRC_TO_DST_SECOND_BYTES': 89.0,
        'DST_TO_SRC_SECOND_BYTES': 73.0,
        'RETRANSMITTED_IN_BYTES': 0,
        'RETRANSMITTED_IN_PKTS': 0,
        'RETRANSMITTED_OUT_BYTES': 0,
        'RETRANSMITTED_OUT_PKTS': 0,
        'SRC_TO_DST_AVG_THROUGHPUT': 389333,
        'DST_TO_SRC_AVG_THROUGHPUT': 474666,
        'NUM_PKTS_UP_TO_128_BYTES': 4,
        'NUM_PKTS_128_TO_256_BYTES': 0,
        'NUM_PKTS_256_TO_512_BYTES': 0,
        'NUM_PKTS_512_TO_1024_BYTES': 0,
        'NUM_PKTS_1024_TO_1514_BYTES': 0,
        'TCP_WIN_MAX_IN': 0,
        'TCP_WIN_MAX_OUT': 0,
        'ICMP_TYPE': 0,
        'ICMP_IPV4_TYPE': 0,
        'DNS_QUERY_ID': 46779,
        'DNS_QUERY_TYPE': 1,
        'DNS_TTL_ANSWER': 60,
        'FTP_COMMAND_RET_CODE': 0,
        'SRC_TO_DST_IAT_MIN': 0,
        'SRC_TO_DST_IAT_MAX': 0,
        'SRC_TO_DST_IAT_AVG': 0,
        'SRC_TO_DST_IAT_STDDEV': 0,
        'DST_TO_SRC_IAT_MIN': 0,
        'DST_TO_SRC_IAT_MAX': 0,
        'DST_TO_SRC_IAT_AVG': 0,
        'DST_TO_SRC_IAT_STDDEV': 0
    }

    # Detect anomaly
    result = detector.detect_anomaly(example_packet)

    # Print result
    print("\nAnomaly Detection Result:")
    print(f"Is anomaly: {result['is_anomaly']}")
    print(f"Anomaly score: {result['anomaly_score']:.6f}")
    print(f"Detection model: {result['detection_model']}")

    if 'ensemble_prediction' in result:
        print(f"\nEnsemble prediction: {result['ensemble_prediction']}")

    if 'rf_binary_prediction' in result:
        print(f"Random Forest prediction: {result['rf_binary_prediction']}")
        print(f"RF attack type: {result['rf_attack_type']}")

    if 'xgb_binary_prediction' in result:
        print(f"XGBoost prediction: {result['xgb_binary_prediction']}")
        print(f"XGB attack type: {result['xgb_attack_type']}")


# For packet capture integration, you can add code here to use libraries like:
# - scapy for live packet capture
# - pyshark for Wireshark integration
# - dpkt for packet parsing


if __name__ == "__main__":
    # Run example usage
    example_usage()
