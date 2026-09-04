"""
Port Scanner Module
Wraps python-nmap to scan a target's top 1000 ports using a TCP connect
scan and return the results as a structured dictionary.
"""

import nmap
import socket
import ipaddress
from urllib.parse import urlparse


def resolve_target(raw_target: str) -> str:
    """Extract the host from a URL, or return the input unchanged if it
    is already a bare hostname or IP address."""
    parsed = urlparse(raw_target)
    if parsed.scheme and parsed.netloc:
        host = parsed.hostname
    else:
        host = raw_target.strip()

    # Resolve hostnames to IP addresses so the value used for scanning
    # matches the value nmap reports results under.
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return host


def is_safe_target(host: str) -> bool:
    """Allow only private/loopback IP addresses or 'localhost' as scan
    targets."""
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        allowed_hostnames = {"localhost"}
        return host.lower() in allowed_hostnames


def scan_target(raw_target: str) -> dict:
    """Run a TCP connect scan (-sT) on the target's top 1000 ports and
    return the results as a dictionary containing target, status,
    open_ports, and error fields."""
    host = resolve_target(raw_target)

    if not is_safe_target(host):
        return {
            "target": host,
            "status": "error",
            "open_ports": [],
            "error": f"'{host}' is not a permitted scan target.",
        }

    scanner = nmap.PortScanner()

    try:
        scanner.scan(hosts=host, arguments="-sT -Pn --top-ports 1000")
    except nmap.PortScannerError as e:
        return {
            "target": host,
            "status": "error",
            "open_ports": [],
            "error": f"Nmap execution failed: {e}",
        }

    if host not in scanner.all_hosts():
        return {
            "target": host,
            "status": "down",
            "open_ports": [],
            "error": "Host did not respond.",
        }

    open_ports = []
    for proto in scanner[host].all_protocols():
        ports = scanner[host][proto].keys()
        for port in sorted(ports):
            port_info = scanner[host][proto][port]
            if port_info["state"] == "open":
                open_ports.append({
                    "port": port,
                    "protocol": proto,
                    "service": port_info.get("name", "unknown"),
                    "state": port_info["state"],
                })

    return {
        "target": host,
        "status": "up",
        "open_ports": open_ports,
        "error": None,
    }


if __name__ == "__main__":
    result = scan_target("localhost")
    print(result)
