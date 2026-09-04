"""
Unified Scan Pipeline
Runs the port scanner, HTTP header check, and SSL/TLS check against a
single target, then merges all results into one combined report with
a consistent findings format and an overall severity summary.
"""

from scanner.port_scanner import scan_target
from scanner.header_check import check_headers
from scanner.ssl_check import check_ssl

# Ports considered risky enough to flag as a finding on their own,
# independent of what service check follows.
RISKY_PORTS = {
    21: "medium",   # FTP - often unencrypted credentials
    23: "high",     # Telnet - unencrypted remote access
    445: "medium",  # SMB - common lateral movement target
    3389: "medium", # RDP - common brute-force target
}

# Severity ranking used to determine the overall/highest severity
# across all findings from all checks.
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}


def _port_findings(port_scan_result: dict) -> list:
    """Convert the port scanner's open_ports list into the same
    finding format used by the other checks, so all results can be
    merged and stored consistently."""
    findings = []
    for entry in port_scan_result.get("open_ports", []):
        port = entry["port"]
        severity = RISKY_PORTS.get(port, "info")
        findings.append({
            "check": f"Open port {port} ({entry['service']})",
            "severity": severity,
            "description": f"Port {port}/{entry['protocol']} is open, running {entry['service']}.",
        })
    return findings


def _overall_severity(findings: list) -> str:
    """Return the highest severity present across all findings, or
    'info' if there are none."""
    if not findings:
        return "info"
    return max(findings, key=lambda f: SEVERITY_RANK.get(f["severity"], 0))["severity"]


def run_scan(raw_target: str) -> dict:
    """Run all three checks against the target and return a single
    merged report. HTTP header checks run only if port 80 is open;
    SSL checks run only if port 443 is open."""
    port_result = scan_target(raw_target)

    all_findings = []
    errors = []

    if port_result["status"] == "error":
        return {
            "target": port_result["target"],
            "overall_severity": "info",
            "findings": [],
            "errors": [port_result["error"]],
        }

    all_findings.extend(_port_findings(port_result))

    open_ports = {entry["port"] for entry in port_result["open_ports"]}

    if 80 in open_ports:
        header_result = check_headers(f"http://{raw_target}")
        if header_result["status"] == "up":
            for finding in header_result["findings"]:
                finding["check"] = f"[HTTP] {finding['check']}"
            all_findings.extend(header_result["findings"])
        elif header_result["error"]:
            errors.append(header_result["error"])

    if 443 in open_ports:
        ssl_result = check_ssl(raw_target, port=443)
        if ssl_result["status"] == "up":
            for finding in ssl_result["findings"]:
                finding["check"] = f"[SSL] {finding['check']}"
            all_findings.extend(ssl_result["findings"])
        elif ssl_result["error"]:
            errors.append(ssl_result["error"])

    return {
        "target": port_result["target"],
        "overall_severity": _overall_severity(all_findings),
        "findings": all_findings,
        "errors": errors,
    }


if __name__ == "__main__":
    result = run_scan("localhost")
    print(result)
