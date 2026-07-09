# main.py
import argparse
from scanner import scan_ports
from banner_grabber import identify_service
from vuln_db import match_banner, check_risky_port
from report_generator import generate_html_report, generate_json_report

def parse_port_range(port_str):
    if "-" in port_str:
        start, end = port_str.split("-")
        return range(int(start), int(end) + 1)
    return [int(port_str)]

def run_scan(target, ports):
    print(f"[*] Scanning {target} on ports {ports.start}-{ports.stop - 1}...")
    open_ports = scan_ports(target, ports)
    print(f"[*] Found {len(open_ports)} open ports: {open_ports}")

    findings = []

    for port in open_ports:
        service_info = identify_service(target, port)
        service_name = "Unknown"
        banner = ""

        if service_info:
            banner = service_info.get("banner") or service_info.get("server", "")
            service_name = banner or "Unknown"

        # Check against vulnerability database
        vuln_match = match_banner(banner)
        if vuln_match:
            findings.append({
                "port": port,
                "service": service_name,
                "issue": vuln_match["issue"],
                "severity": vuln_match["severity"]
            })

        # Check if port itself is inherently risky
        risky = check_risky_port(port)
        if risky:
            findings.append({
                "port": port,
                "service": risky["name"],
                "issue": risky["issue"],
                "severity": risky["severity"]
            })

        # Check missing security headers (HTTP ports only)
        if service_info and "missing_headers" in service_info and service_info["missing_headers"]:
            findings.append({
                "port": port,
                "service": service_name,
                "issue": f"Missing security headers: {', '.join(service_info['missing_headers'])}",
                "severity": "Low"
            })

        if not vuln_match and not risky:
            findings.append({
                "port": port,
                "service": service_name or "Unknown",
                "issue": "Open port, no known issues detected",
                "severity": "Info"
            })

    return findings

def main():
    parser = argparse.ArgumentParser(description="Mini Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target IP or hostname")
    parser.add_argument("--ports", default="1-1024", help="Port range, e.g. 1-1024")
    parser.add_argument("--output", default="report", help="Output file base name (no extension)")
    args = parser.parse_args()

    ports = parse_port_range(args.ports)
    findings = run_scan(args.target, ports)

    html_file = generate_html_report(findings, args.target, f"{args.output}.html")
    json_file = generate_json_report(findings, args.target, f"{args.output}.json")

    high = sum(1 for f in findings if f["severity"] == "High")
    med = sum(1 for f in findings if f["severity"] == "Medium")
    low = sum(1 for f in findings if f["severity"] == "Low")

    print(f"\n[*] Scan complete. {len(findings)} findings — {high} High, {med} Medium, {low} Low")
    print(f"[*] Reports saved: {html_file}, {json_file}")

if __name__ == "__main__":
    main()