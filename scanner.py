# scanner.py
import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(target, port, timeout=1):
    """Try connecting to a single port. Returns port number if open, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            return port if result == 0 else None
    except socket.error:
        return None

def scan_ports(target, ports=range(1, 1025), max_workers=100):
    """Scan a range of ports concurrently. Returns sorted list of open ports."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, target, p): p for p in ports}
        for future in futures:
            result = future.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports)

if __name__ == "__main__":
    # quick standalone test
    target = "127.0.0.1"
    print(f"Scanning {target}...")
    found = scan_ports(target, ports=range(1, 1025))
    print(f"Open ports: {found}")