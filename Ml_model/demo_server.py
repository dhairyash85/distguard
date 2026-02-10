#!/usr/bin/env python3
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from anomaly_detector_nfqueue import BlockchainBridge

# Initialize Blockchain Bridge
# We use this to query if an IP is blocked
print("Initializing Blockchain Bridge...")
try:
    # Pass None to auto-detect address from CLI
    bridge = BlockchainBridge(validator_address=None)
except Exception as e:
    print(f"Error initializing bridge: {e}")
    sys.exit(1)

class ProtectedHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        client_ip = self.client_address[0]
        
        # 1. Check Blockchain
        # In a real high-performance app, you would cache this result
        is_blocked = bridge.is_ip_blocked(client_ip)
        
        if is_blocked:
            print(f"⛔ BLOCKED access attempt from malicious IP: {client_ip}")
            self.send_response(403)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>403 Forbidden</h1><p>Your IP has been flagged as malicious by the blockchain.</p>")
        else:
            print(f"✅ Allowed access from: {client_ip}")
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Welcome!</h1><p>This is a protected server.</p>")

    def log_message(self, format, *args):
        # Override to reduce console clutter
        return

def main():
    server = HTTPServer((HOST, PORT), ProtectedHandler)
    print(f"🚀 Protected Server running on http://{HOST}:{PORT}")
    print("   (Checks blockchain for banned IPs on every request)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    print("Server stopped.")

if __name__ == "__main__":
    main()
