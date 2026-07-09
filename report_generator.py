# report_generator.py
import json
from datetime import datetime

def generate_html_report(findings, target, output="report.html"):
    rows = ""
    for f in findings:
        color = {"High": "#ff4d4d", "Medium": "#ffb84d", "Low": "#4dff88", "Info": "#4da6ff"}.get(f["severity"], "#ccc")
        rows += f"""
        <tr>
            <td>{f['port']}</td>
            <td>{f['service']}</td>
            <td>{f['issue']}</td>
            <td style="color:{color}; font-weight:bold;">{f['severity']}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html>
<head>
<title>Vulnerability Scan Report</title>
<style>
    body {{ font-family: Arial, sans-serif; background: #0d1117; color: #e6edf3; padding: 30px; }}
    h1 {{ color: #4dff88; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
    th, td {{ border: 1px solid #30363d; padding: 10px; text-align: left; }}
    th {{ background: #161b22; }}
    .meta {{ color: #8b949e; }}
</style>
</head>
<body>
    <h1>Vulnerability Scan Report</h1>
    <p class="meta">Target: {target} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p class="meta">Total findings: {len(findings)}</p>
    <table>
        <tr><th>Port</th><th>Service</th><th>Issue</th><th>Severity</th></tr>
        {rows if rows else '<tr><td colspan="4">No issues found</td></tr>'}
    </table>
</body>
</html>"""

    with open(output, "w") as file:
        file.write(html)
    return output

def generate_json_report(findings, target, output="report.json"):
    data = {
        "target": target,
        "generated": datetime.now().isoformat(),
        "total_findings": len(findings),
        "findings": findings
    }
    with open(output, "w") as file:
        json.dump(data, file, indent=2)
    return output