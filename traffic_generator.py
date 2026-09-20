"""
NIDS Live Demonstration & Traffic Generator
Run this script in a secondary terminal to generate traffic and simulate attacks for the judges.
"""

import sys
import time
import socket
import urllib.request

TARGET_HOST = "127.0.0.1"

def print_banner():
    print("=" * 60)
    print("      AIoT NIDS Live Demonstration Traffic Generator       ")
    print("=" * 60)
    print("Select a traffic profile to generate:")
    print("  [1] Normal Web Traffic (Benign / python.exe)")
    print("  [2] Simulate Port Scan / Reconnaissance (Probe Attack)")
    print("  [3] Simulate High-Rate Traffic Burst (DoS / DDoS Attack)")
    print("  [4] Simulate Protocol Brute Force (SSH/FTP Patator)")
    print("  [5] Run Continuous Mixed Demo (Benign + Attacks)")
    print("  [q] Quit")
    print("=" * 60)

def generate_benign():
    print("\n[+] Generating Normal Web Traffic (Benign)...")
    urls = [
        "http://httpbin.org/get",
        "http://example.com",
        "http://httpbin.org/headers",
        "http://httpbin.org/ip"
    ]
    for url in urls:
        try:
            print(f"  -> Sending HTTP GET request to {url}...")
            req = urllib.request.Request(url, headers={'User-Agent': 'DemoBrowser/1.0'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = resp.read()
                print(f"     [OK] Received {len(data)} bytes (Status {resp.status})")
            time.sleep(1)
        except Exception as e:
            print(f"     [!] Request completed/skipped: {e}")
    print("[✓] Normal traffic generation complete. Check the live dashboard!\n")

def simulate_probe():
    print("\n[!] Simulating Port Scan / Reconnaissance (Probe Attack)...")
    target_ip = "127.0.0.1"
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080, 8443, 9000, 27017]
    print(f"  -> Scanning ports on {target_ip} rapidly (SYN probe simulation)...")
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.15)
        try:
            s.connect((target_ip, port))
            s.close()
        except Exception:
            pass
        finally:
            s.close()
        time.sleep(0.05)
    print("[✓] Port scan simulation complete. Check dashboard for 'Probe' alert!\n")

def simulate_dos():
    print("\n[!] Simulating High-Rate Burst Traffic (DoS / DDoS Simulation)...")
    target_ip = "127.0.0.1"
    target_port = 5000  # NIDS server port
    print(f"  -> Sending rapid burst of {40} TCP socket connections to {target_ip}:{target_port}...")
    for i in range(40):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((target_ip, target_port))
            s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            s.close()
        except Exception:
            pass
        time.sleep(0.01)
    print("[✓] DoS burst simulation complete. Check dashboard for elevated risk!\n")

def simulate_patator():
    print("\n[!] Simulating SSH/FTP Protocol Brute-Force (Patator Attack)...")
    target_ip = "127.0.0.1"
    ports = [22, 21] # SSH and FTP
    for port in ports:
        service = "SSH (22)" if port == 22 else "FTP (21)"
        print(f"  -> Simulating rapid connection attempts on {service}...")
        for attempt in range(12):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                s.connect((target_ip, port))
                s.sendall(b"SSH-2.0-OpenSSH_8.2\r\n" if port == 22 else b"USER admin\r\n")
                s.close()
            except Exception:
                pass
            time.sleep(0.05)
    print("[✓] Patator simulation complete. Check dashboard for alerts!\n")

def run_mixed_demo():
    print("\n[*] Running Continuous Live Demonstration Mode (Ctrl+C to stop)...")
    cycle = 1
    try:
        while True:
            print(f"\n--- [Cycle {cycle}] Generating Normal Flow ---")
            generate_benign()
            time.sleep(2)
            
            print(f"\n--- [Cycle {cycle}] Injecting Probe Attack ---")
            simulate_probe()
            time.sleep(2)

            print(f"\n--- [Cycle {cycle}] Injecting DoS Burst ---")
            simulate_dos()
            time.sleep(2)

            cycle += 1
    except KeyboardInterrupt:
        print("\n[!] Continuous demo stopped by user.\n")

def main():
    while True:
        print_banner()
        try:
            choice = input("Enter choice (1-5, q): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            sys.exit(0)

        if choice == '1':
            generate_benign()
        elif choice == '2':
            simulate_probe()
        elif choice == '3':
            simulate_dos()
        elif choice == '4':
            simulate_patator()
        elif choice == '5':
            run_mixed_demo()
        elif choice.lower() in ['q', 'exit', 'quit']:
            print("Exiting.")
            break
        else:
            print("[!] Invalid option. Please select 1-5 or q.")

if __name__ == '__main__':
    main()
