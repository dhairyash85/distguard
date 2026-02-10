#!/usr/bin/env python3
"""
Blockchain Firewall Enforcer
Continuously syncs malicious IPs from blockchain and blocks them with iptables
"""
import subprocess
import json
import time
import sys

class FirewallEnforcer:
    def __init__(self, node="tcp://localhost:26657"):
        self.node = node
        self.blocked_ips = set()

    def get_malicious_ips_from_blockchain(self):
        """Query blockchain for all malicious IPs."""
        try:
            result = subprocess.run(
                ["/home/ditya/go/bin/cybersecurityd", "query", "threatintel",
                 "list-malicious-ips", "--node", self.node, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                print(f"[Error] Failed to query blockchain: {result.stderr}")
                return []

            data = json.loads(result.stdout)
            # Handle both possible response formats
            ips = data.get("ips", []) or [entry.get("ip") for entry in data.get("maliciousIps", [])]
            return [ip for ip in ips if ip]  # Filter out None values

        except Exception as e:
            print(f"[Error] Exception querying blockchain: {e}")
            return []

    def block_ip(self, ip):
        """Block an IP using iptables."""
        try:
            # Block incoming traffic from this IP
            subprocess.run(
                ["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            # Block outgoing traffic to this IP
            subprocess.run(
                ["sudo", "iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            # Block forwarding
            subprocess.run(
                ["sudo", "iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            subprocess.run(
                ["sudo", "iptables", "-I", "FORWARD", "-d", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            print(f"[Firewall] ✓ Blocked {ip}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"[Firewall] ✗ Failed to block {ip}: {e.stderr}")
            return False

    def unblock_ip(self, ip):
        """Unblock an IP using iptables."""
        try:
            # Remove all rules for this IP (may need multiple attempts)
            for _ in range(5):  # Try up to 5 times in case there are duplicate rules
                subprocess.run(
                    ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                    capture_output=True
                )
                subprocess.run(
                    ["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                    capture_output=True
                )
                subprocess.run(
                    ["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"],
                    capture_output=True
                )
                subprocess.run(
                    ["sudo", "iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"],
                    capture_output=True
                )
            print(f"[Firewall] ✓ Unblocked {ip}")
            return True
        except Exception as e:
            print(f"[Firewall] ✗ Failed to unblock {ip}: {e}")
            return False

    def is_ip_blocked_in_firewall(self, ip):
        """Check if IP is currently blocked in iptables."""
        try:
            result = subprocess.run(
                ["sudo", "iptables", "-L", "INPUT", "-n"],
                capture_output=True,
                text=True
            )
            return ip in result.stdout
        except Exception:
            return False

    def sync_firewall(self):
        """Sync firewall rules with blockchain state."""
        # Get current malicious IPs from blockchain
        blockchain_ips = set(self.get_malicious_ips_from_blockchain())

        # Find IPs that need to be blocked (in blockchain but not in our blocked set)
        ips_to_block = blockchain_ips - self.blocked_ips

        # Find IPs that need to be unblocked (in our blocked set but not in blockchain)
        ips_to_unblock = self.blocked_ips - blockchain_ips

        # Block new IPs
        for ip in ips_to_block:
            if self.block_ip(ip):
                self.blocked_ips.add(ip)

        # Unblock removed IPs
        for ip in ips_to_unblock:
            if self.unblock_ip(ip):
                self.blocked_ips.remove(ip)

        if ips_to_block or ips_to_unblock:
            print(f"[Sync] Currently blocking {len(self.blocked_ips)} IP(s): {sorted(self.blocked_ips)}")

        return len(blockchain_ips)

    def run_once(self):
        """Run a single sync cycle."""
        print("\n" + "="*60)
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Syncing firewall with blockchain...")
        print("="*60)

        count = self.sync_firewall()

        print(f"\n[Status] Blockchain has {count} malicious IP(s)")
        print(f"[Status] Firewall is blocking {len(self.blocked_ips)} IP(s)")

        if self.blocked_ips:
            print("\n[Blocked IPs]")
            for ip in sorted(self.blocked_ips):
                print(f"  🔒 {ip}")

    def run_continuous(self, interval=10):
        """Run continuous sync every N seconds."""
        print("="*60)
        print("Blockchain Firewall Enforcer")
        print("="*60)
        print(f"Syncing every {interval} seconds. Press Ctrl+C to stop.")
        print("="*60)

        try:
            while True:
                self.run_once()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n\n[Shutdown] Stopping enforcer...")
            print("[Note] Blocked IPs will remain blocked. Run with --clear to unblock all.")

    def clear_all(self):
        """Remove all blocked IPs from firewall."""
        print("\n[Cleanup] Clearing all firewall rules...")
        for ip in list(self.blocked_ips):
            self.unblock_ip(ip)
        self.blocked_ips.clear()
        print("✓ All IPs unblocked")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Blockchain Firewall Enforcer")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    parser.add_argument("--clear", action="store_true", help="Clear all firewall rules and exit")
    parser.add_argument("--interval", type=int, default=10, help="Sync interval in seconds (default: 10)")
    parser.add_argument("--node", default="tcp://localhost:26657", help="Blockchain node address")

    args = parser.parse_args()

    enforcer = FirewallEnforcer(node=args.node)

    if args.clear:
        enforcer.clear_all()
    elif args.once:
        enforcer.run_once()
    else:
        enforcer.run_continuous(interval=args.interval)


if __name__ == "__main__":
    main()
