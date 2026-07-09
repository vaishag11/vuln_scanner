# banner_grabber.py
import socket
import requests

def grab_banner(target, port, timeout=2):
    """Try to read a raw banner from a TCP service (SSH, FTP, SMTP, etc.)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner if banner else None
    except (socket.timeout, socket.error, ConnectionRefusedError):
        return None

def check_http_headers(target, port, timeout=3):
    """For web ports, grab the Server header and check for missing security headers."""
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{target}:{port}"
    try:
        r = requests.get(url, timeout=timeout, verify=False)
        server = r.headers.get("Server", "Unknown")
        missing_headers = []
        for header in ["Strict-Transport-Security", "X-Frame-Options", "Content-Security-Policy"]:
            if header not in r.headers:
                missing_headers.append(header)
        return {"server": server, "missing_headers": missing_headers}
    except requests.RequestException:
        return None

def identify_service(target, port):
    """Pick the right grabbing strategy based on port."""
    if port in (80, 443, 8080, 8443):
        return check_http_headers(target, port)
    else:
        banner = grab_banner(target, port)
        return {"banner": banner} if banner else None