# vuln_db.py

# Map of banner substrings -> known issues
VULN_DB = {
    "vsftpd 2.3.4": {"severity": "High", "issue": "Known backdoor vulnerability (CVE-2011-2523)"},
    "ProFTPD 1.3.3": {"severity": "High", "issue": "Backdoor vulnerability in this version"},
    "OpenSSH 4.": {"severity": "High", "issue": "Very outdated OpenSSH, multiple known CVEs"},
    "OpenSSH 5.": {"severity": "Medium", "issue": "Outdated OpenSSH version"},
    "OpenSSH 6.": {"severity": "Low", "issue": "Older OpenSSH version, check for updates"},
    "Apache/2.2": {"severity": "Medium", "issue": "EOL Apache version, no longer supported"},
    "Apache/2.4.7": {"severity": "Medium", "issue": "Known vulnerable Apache 2.4.7 build"},
    "nginx/1.1": {"severity": "Medium", "issue": "Outdated nginx version"},
    "MySQL 5.5": {"severity": "Medium", "issue": "Outdated MySQL version"},
    "Microsoft-IIS/6.0": {"severity": "High", "issue": "Very outdated IIS, multiple known exploits"},
}

# Ports that are inherently risky if exposed, regardless of banner
RISKY_PORTS = {
    21: {"name": "FTP", "severity": "Medium", "issue": "FTP transmits credentials in plaintext"},
    23: {"name": "Telnet", "severity": "High", "issue": "Telnet transmits everything in plaintext"},
    25: {"name": "SMTP", "severity": "Low", "issue": "Open mail relay risk if misconfigured"},
    80: {"name": "HTTP", "severity": "Low", "issue": "Unencrypted HTTP, consider HTTPS redirect"},
    135: {"name": "MSRPC", "severity": "Medium", "issue": "Windows RPC exposed, common attack surface"},
    139: {"name": "NetBIOS", "severity": "Medium", "issue": "NetBIOS exposed, legacy Windows sharing risk"},
    445: {"name": "SMB", "severity": "High", "issue": "SMB exposed, common ransomware/exploit vector"},
    3389: {"name": "RDP", "severity": "High", "issue": "RDP exposed to network, brute-force risk"},
}

def match_banner(banner):
    """Check a banner string against known vulnerable versions."""
    if not banner:
        return None
    for pattern, info in VULN_DB.items():
        if pattern.lower() in banner.lower():
            return info
    return None

def check_risky_port(port):
    """Check if a port is inherently risky."""
    return RISKY_PORTS.get(port)