#!/usr/bin/env python3
import requests
import threading
import time
import sys

TARGET_URL = "http://127.0.0.1:8080"
DURATION_SECONDS = 30
REQUESTS_PER_SECOND = 50  # Adjust based on system capability

def send_requests(stop_event):
    while not stop_event.is_set():
        try:
            response = requests.get(TARGET_URL, timeout=1)
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
