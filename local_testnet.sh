#!/bin/bash
# 1-Click Local Testnet (4 Nodes)
# Automatically configures ports, genesis, and peeling.

CHAIN_ID="cybersecurity"
# Base directories (e.g. ~/.cybersecurity-node0, ~/.cybersecurity-node1...)
BASE_DIR="$HOME/.cybersecurity-testnet"
NUM_NODES=4

echo "=========================================="
echo "🚀 Starting Local 4-Node Testnet"
echo "=========================================="
echo ""

# Cleanup
echo "🧹 Cleaning previous testnet data..."
rm -rf "$BASE_DIR"

# 1. Initialize Nodes
echo "🛠 Initializing $NUM_NODES nodes..."
for i in $(seq 0 $(($NUM_NODES - 1))); do
    NODE_DIR="$BASE_DIR/node$i"
    MONIKER="node$i"
    
    # Init
    cybersecurityd init "$MONIKER" --chain-id "$CHAIN_ID" --home "$NODE_DIR" > /dev/null 2>&1
    
    # Set min-gas-prices (Critical)
    APP_TOML="$NODE_DIR/config/app.toml"
    sed -i 's/minimum-gas-prices = ""/minimum-gas-prices = "0stake"/g' "$APP_TOML"
done

# 2. Setup Genesis (Use Node 0 as Validator)
echo "🧬 Setting up Genesis..."
NODE0_DIR="$BASE_DIR/node0"
VALIDATOR_ADDR=$(cybersecurityd keys add validator --keyring-backend test --home "$NODE0_DIR" --output json | jq -r .address)

# Add account and gentx
cybersecurityd genesis add-genesis-account "$VALIDATOR_ADDR" 100000000000stake --keyring-backend test --home "$NODE0_DIR" > /dev/null 2>&1
cybersecurityd genesis gentx validator 1000000000stake --chain-id "$CHAIN_ID" --keyring-backend test --home "$NODE0_DIR" > /dev/null 2>&1
cybersecurityd genesis collect-gentxs --home "$NODE0_DIR" > /dev/null 2>&1

# Copy genesis to other nodes
for i in $(seq 1 $(($NUM_NODES - 1))); do
    cp "$NODE0_DIR/config/genesis.json" "$BASE_DIR/node$i/config/genesis.json"
done

# 3. Configure Ports
# Offset: Node i uses BasePort + (i * 10)
# Base Ports: RPC=26657, P2P=26656, ABCI=26658, PPROF=6060, API=1317, GRPC=9090, GRPC-WEB=9091
echo "🔧 Configuring Ports..."

for i in $(seq 0 $(($NUM_NODES - 1))); do
    NODE_DIR="$BASE_DIR/node$i"
    CONFIG="$NODE_DIR/config/config.toml"
    APP="$NODE_DIR/config/app.toml"
    OFFSET=$(($i * 10))
    
    # Calculate ports
    RPC=$((26657 + $OFFSET))
    P2P=$((26656 + $OFFSET))
    ABCI=$((26658 + $OFFSET))
    PPROF=$((6060 + $OFFSET))
    API=$((1317 + $OFFSET))
    GRPC=$((9090 + $OFFSET))
    GRPC_WEB=$((9091 + $OFFSET))
    
    # Replace Config
    sed -i "s#tcp://127.0.0.1:26657#tcp://127.0.0.1:$RPC#g" "$CONFIG"
    sed -i "s#tcp://0.0.0.0:26656#tcp://0.0.0.0:$P2P#g" "$CONFIG"
    sed -i "s#tcp://127.0.0.1:26658#tcp://127.0.0.1:$ABCI#g" "$CONFIG"
    sed -i "s#localhost:6060#localhost:$PPROF#g" "$CONFIG"
    
    # Replace App
    sed -i "s#0.0.0.0:9090#0.0.0.0:$GRPC#g" "$APP"
    sed -i "s#0.0.0.0:9091#0.0.0.0:$GRPC_WEB#g" "$APP"
    sed -i "s#tcp://0.0.0.0:1317#tcp://0.0.0.0:$API#g" "$APP"
done

# 4. Form Mesh Network (Get Node IDs)
echo "🔗 Gathering Node IDs..."
PEERS=""
for i in $(seq 0 $(($NUM_NODES - 1))); do
    NODE_DIR="$BASE_DIR/node$i"
    ID=$(cybersecurityd tendermint show-node-id --home "$NODE_DIR")
    OFFSET=$(($i * 10))
    PORT=$((26656 + $OFFSET))
    IP="127.0.0.1"
    
    if [ -z "$PEERS" ]; then
        PEERS="$ID@$IP:$PORT"
    else
        PEERS="$PEERS,$ID@$IP:$PORT"
    fi
done

echo "Peers: $PEERS"

# 5. Apply Peers to Config
for i in $(seq 0 $(($NUM_NODES - 1))); do
    NODE_DIR="$BASE_DIR/node$i"
    CONFIG="$NODE_DIR/config/config.toml"
    sed -i "s#persistent_peers = \"\"#persistent_peers = \"$PEERS\"#g" "$CONFIG"
done

# 6. Start All Nodes
echo "🚀 Starting Nodes..."
for i in $(seq 0 $(($NUM_NODES - 1))); do
    NODE_DIR="$BASE_DIR/node$i"
    LOG_FILE="$BASE_DIR/node$i.log"
    echo "Starting Node $i (Logs: $LOG_FILE)..."
    nohup cybersecurityd start --home "$NODE_DIR" > "$LOG_FILE" 2>&1 &
done

echo ""
echo "✅ Testnet Running!"
echo "Check logs with: tail -f $BASE_DIR/node0.log"
echo "Stop all with: pkill cybersecurityd"
