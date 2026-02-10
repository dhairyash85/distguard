#!/bin/bash
# Quick Start Script for NFQUEUE-Based Detection System
# Run this script with sudo to start the real-time detection system

set -e

echo "=========================================="
echo "NFQUEUE Blockchain Cybersecurity System"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Error: This script must be run as root (use sudo)"
    exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ML_DIR="$SCRIPT_DIR"

echo "📁 Working directory: $ML_DIR"
echo ""

# Check if models exist
if [ ! -f "$ML_DIR/model/isolation_forest_model.pkl" ]; then
    echo "❌ Error: ML models not found in $ML_DIR/model/"
    echo "Please ensure the trained models are in the correct location."
    exit 1
fi

echo "✅ ML models found"
echo ""

# Check if blockchain is running
echo "🔍 Checking blockchain status..."
if ! command -v cybersecurityd &> /dev/null; then
    echo "⚠️  Warning: cybersecurityd not found in PATH"
    echo "Make sure the blockchain is installed and running"
else
    if pgrep -x "cybersecurityd" > /dev/null; then
        echo "✅ Blockchain is running"
    else
        echo "⚠️  Warning: Blockchain doesn't appear to be running"
        echo "Start it with: cybersecurityd start"
    fi
fi
echo ""

# Setup iptables rules
# (Passive Mode - No iptables needed)
echo "🔧 Passive Mode: No iptables rules needed."
echo ""

# Check Python dependencies
# Check for virtual environment and set PYTHON_CMD
if [ -f "$ML_DIR/venv/bin/python" ]; then
    PYTHON_CMD="$ML_DIR/venv/bin/python"
    echo "✅ Using virtual environment: $PYTHON_CMD"
else
    PYTHON_CMD="python3"
    echo "⚠️  Using system python3 (ensure dependencies are installed globally or in venv)"
fi
echo ""

# Check Python dependencies
echo "🔍 Checking Python dependencies..."
if $PYTHON_CMD -c "import scapy.all, joblib, numpy, pandas" 2>/dev/null; then
    echo "✅ Python dependencies installed"
else
    echo "❌ Error: Missing Python dependencies"
    echo "Install with: $PYTHON_CMD -m pip install scapy joblib numpy pandas scikit-learn"
    exit 1
fi
echo ""

# Start the detecto
echo "=========================================="
echo "🚀 Starting Passive Anomaly Detector"
echo "=========================================="
echo ""
echo "Press Ctrl+C to stop"
echo ""

cd "$ML_DIR"
$PYTHON_CMD anomaly_detector_nfqueue.py

# Cleanup on exit
echo ""
echo "✅ Cleanup complete"
