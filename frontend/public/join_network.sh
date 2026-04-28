#!/bin/bash
# Helper script to join an existing blockchain network
# Configure the variables below or follow the prompts

CHAIN_ID="cybersecurity"
HOME_DIR="$HOME/.cybersecurity"

echo "=========================================="
echo "🌐 Join Blockchain Network"
echo "=========================================="
echo ""

# 1. Initialize
if [ -d "$HOME_DIR/config" ]; then
    echo "⚠️  Found existing data in $HOME_DIR"
    read -p "Reset and overwrite? (y/N) " confirm
    if [[ "$confirm" != "y" ]]; then
        echo "Aborting."
        exit 1
    fi
    rm -rf "$HOME_DIR"
fi

read -p "Enter a name for this node (moniker): " MONIKER
if [ -z "$MONIKER" ]; then MONIKER="worker-node"; fi

echo "Initializing node..."
cybersecurityd init "$MONIKER" --chain-id "$CHAIN_ID" --home "$HOME_DIR" > /dev/null 2>&1

# Set minimum-gas-prices to avoid start errors
APP_TOML="$HOME_DIR/config/app.toml"
sed -i 's/minimum-gas-prices = ""/minimum-gas-prices = "0stake"/g' "$APP_TOML"
sed -i 's/minimum-gas-prices = "0stake"/minimum-gas-prices = "0stake"/g' "$APP_TOML"

# 2. Get Genesis
echo ""
echo "📝 You need the 'genesis.json' from the main node."
echo "Paste the content of genesis.json into $HOME_DIR/config/genesis.json"
echo "OR copy the file manually now."
read -p "Press ENTER when genesis.json is ready in $HOME_DIR/config/"

# 3. Configure Peers
echo ""
echo "🔗 Connection Info"
echo "You need the 'persistent_peers' string from the main node."
echo "Format: <node_id>@<ip_address>:26656"
read -p "Enter Persistent Peer: " PEER

if [ -n "$PEER" ]; then
    CONFIG_TOML="$HOME_DIR/config/config.toml"
    sed -i "s#persistent_peers = \"\"#persistent_peers = \"$PEER\"#g" "$CONFIG_TOML"
    echo "✅ Peer configured."
else
    echo "⚠️  No peer entered. You will need to add it manually to config.toml later."
fi

echo ""
echo "✅ Setup complete!"
echo "Start the node with:"
echo "  cybersecurityd start"
