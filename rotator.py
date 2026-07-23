import socket
import time
import sys

def renew_tor_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('127.0.0.1', 9051))
            # Authenticate with the password we set in torrc
            s.sendall(b'AUTHENTICATE "tornet"\r\n')
            response = s.recv(1024)
            if b"250 OK" in response:
                s.sendall(b'SIGNAL NEWNYM\r\n')
                response = s.recv(1024)
                if b"250 OK" in response:
                    print("[Rotator] Successfully requested new IP from Tor.", flush=True)
                else:
                    print(f"[Rotator] Failed to send NEWNYM: {response}", flush=True)
            else:
                print(f"[Rotator] Auth failed: {response}", flush=True)
    except Exception as e:
        print(f"[Rotator] Tor Control Error: {e}", flush=True)

if __name__ == "__main__":
    print("[Rotator] Starting Tor IP Rotation Daemon...")
    while True:
        renew_tor_ip()
        # Rotate IP every 15 seconds
        time.sleep(15)
