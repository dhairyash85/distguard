#!/usr/bin/env python3
import requests
import threading
import time
import sys

TARGET_URL = "http://127.0.0.1:5000/analyze-flow"
DURATION_SECONDS = 30
REQUESTS_PER_SECOND = 50  # Adjust based on system capability

def send_requests(stop_event):
    # Simulated flow data that mimics a DoS pattern.
    # The API expects {"features": {...}} with the ML model's column names.
    flow_data = {
        "features": {
            "IPV4_SRC_ADDR": "192.168.1.105",
            "IPV4_DST_ADDR": "10.0.0.1",
            "L4_SRC_PORT": 12345,
            "L4_DST_PORT": 80,
            "PROTOCOL": 6,
            "FLOW_DURATION_MILLISECONDS": 1,
            "IN_BYTES": 999999,
            "OUT_BYTES": 0,
            "IN_PKTS": 1000,
            "OUT_PKTS": 0,
            "TCP_FLAGS": 2,
            "TOTAL_FLOWS_EXP": 50000,
        }
    }
    while not stop_event.is_set():
        try:
            response = requests.post(TARGET_URL, json=flow_data, timeout=1)
            status = response.status_code
            if status == 403:
                print(f"🔥 BLOCK CONFIRMED! Server returned 403 Forbidden.")
                # We stop early if blocked to show success
                stop_event.set()
                break
            elif status == 200:
                pass
                # print(".", end="", flush=True)
            else:
                print(f"Status: {status}")
        except requests.exceptions.RequestException:
            pass
        # time.sleep(0.01) # Blast as fast as possible

def main():
    print(f"⚔️  Starting DoS Simulation against {TARGET_URL}")
    print(f"    Duration: {DURATION_SECONDS}s")
    print("    Goal: Trigger anomaly detector -> Block on Chain -> Server 403")
    print("----------------------------------------------------------------")

    stop_event = threading.Event()
    threads = []
    
    # Start threads
    for _ in range(10): # 10 concurrent threads
        t = threading.Thread(target=send_requests, args=(stop_event,))
        t.start()
        threads.append(t)

    start_time = time.time()
    try:
        while time.time() - start_time < DURATION_SECONDS:
            if stop_event.is_set():
                break
            time.sleep(1)
            print(f"Sending traffic... ({int(time.time() - start_time)}s)")
    except KeyboardInterrupt:
        print("\nStopping...")
        stop_event.set()

    stop_event.set()
    for t in threads:
        t.join()

    print("\n----------------------------------------------------------------")
    if stop_event.is_set():
        print("✅ SUCCESS: Attack was blocked by the server!")
    else:
        print("⚠️  Attack finished without being blocked.")
        print("   (Ensure detector is running and model threshold is low enough)")

if __name__ == "__main__":
    main()
