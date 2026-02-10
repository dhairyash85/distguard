#!/bin/bash
# Start a second node on the SAME machine for testing multi-node setup.
# Uses unexpected ports (26659 RPC, 26658 P2P, etc.)

CHAIN_ID="cybersecurity"
HOME_DIR="$HOME/.cybersecurity"
NODE2_HOME="$HOME/.cybersecurity2"

echo "=========================================="
echo "🚀 Starting Local Test Node #2"
echo "=========================================="
echo ""

# 1. Clean previous run
echo "🧹 Cleaning previous Node 2 data..."
rm -rf "$NODE2_HOME"

# 2. Initialize Node 2
echo "init..."
cybersecurityd init node2 --chain-id "$CHAIN_ID" --home "$NODE2_HOME" > /dev/null 2>&1

# 3. Copy Genesis from Node 1 (Must be identical)
echo "🧬 Copying genesis from Node 1..."
cp "$HOME_DIR/config/genesis.json" "$NODE2_HOME/config/genesis.json"

# 4. Configure Ports to avoid conflict with Node 1
# Node 1 uses default: 26657 (RPC), 26656 (P2P), 26658 (ABCI), 9090 (GRPC), 1317 (API)
# Node 2 will use:   26659 (RPC), 26661 (P2P), 26662 (ABCI), 9092 (GRPC), 1318 (API)

echo "🔧 Configuring ports for Node 2..."
CONFIG_TOML="$NODE2_HOME/config/config.toml"
APP_TOML="$NODE2_HOME/config/app.toml"

# Update config.toml
sed -i 's#tcp://127.0.0.1:26657#tcp://127.0.0.1:26659#g' "$CONFIG_TOML"  # RPC
sed -i 's#tcp://0.0.0.0:26656#tcp://0.0.0.0:26661#g' "$CONFIG_TOML"      # P2P Listen
sed -i 's#tcp://127.0.0.1:26658#tcp://127.0.0.1:26662#g' "$CONFIG_TOML"  # Proxy App (ABCI)
sed -i 's#pprof_laddr = "localhost:6060"#pprof_laddr = "localhost:6061"#g' "$CONFIG_TOML"

# Update app.toml
sed -i 's#0.0.0.0:9090#0.0.0.0:9092#g' "$APP_TOML"                       # GRPC
sed -i 's#0.0.0.0:9091#0.0.0.0:9093#g' "$APP_TOML"                       # GRPC Web
sed -i 's#tcp://0.0.0.0:1317#tcp://0.0.0.0:1318#g' "$APP_TOML"           # API

# Set minimum-gas-prices (CRITICAL FIX)
sed -i 's/minimum-gas-prices = ""/minimum-gas-prices = "0stake"/g' "$APP_TOML"
sed -i 's/minimum-gas-prices = "0stake"/minimum-gas-prices = "0stake"/g' "$APP_TOML" # Redundant safety

# 5. Connect to Node 1
echo "🔗 Getting Node 1 ID..."
NODE1_ID=$(cybersecurityd tendermint show-node-id --home "$HOME_DIR")
NODE1_P2P="tcp://127.0.0.1:26656"
# Explicitly use 127.0.0.1 and port 26656 for Node 1
PEER="$NODE1_ID@127.0.0.1:26656"

echo "Connecting to Peer: $PEER"
sed -i "s#persistent_peers = \"\"#persistent_peers = \"$PEER\"#g" "$CONFIG_TOML"

# 6. Start Node 2
echo "✅ Node 2 Configured."
echo "Starting Node 2 logs (Press Ctrl+C to stop)..."
echo ""
cybersecurityd start --home "$NODE2_HOME"
