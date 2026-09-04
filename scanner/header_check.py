"""
HTTP Header Check Module
Connects to a target URL and inspects the response headers for:
1. Missing security headers (hardening gaps).
2. Present information-leak headers (software/version disclosure).
Each finding is returned with a severity rating so results can feed
directly into the reporting/storage layer.
"""

import requests

from scanner.port_scanner import resolve_target, is_safe_target


# Security headers that should be present. Missing any of these is
# flagged as a hardening weakness.
REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": "medium",
    "X-Frame-Options": "medium",
    "X-Content-Type-Options": "low",
    "Content-Security-Policy": "medium",
}

# Headers that should ideally not reveal software/version details.
INFO_LEAK_HEADERS = ["Server", "X-Powered-By"]


def classify_info_leak(header_value: str) -> str:
    """Return 'medium' if the header value includes a version number
    (more useful to an attacker), otherwise 'low' for a bare product
    name with no version."""
    return "medium" if any(char.isdigit() for char in header_value) else "low"


def check_headers(raw_target: str) -> dict:
    """Send a GET request to the target and evaluate its response
    headers. Returns a dictionary containing target, status, findings
    (list of dicts with check/severity/description), and error."""
    host = resolve_target(raw_target)

    if not is_safe_target(host):
        return {
            "target": host,
            "status": "error",
            "findings": [],
            "error": f"'{host}' is not a permitted scan target.",
        }

    url = raw_target if raw_target.startswith("http") else f"http://{raw_target}"

    try:
        response = requests.get(url, timeout=5)
    except requests.exceptions.RequestException as e:
        return {
            "target": host,
            "status": "error",
            "findings": [],
            "error": f"Request failed: {e}",
        }

    headers = response.headers
    findings = []

    for header, severity in REQUIRED_SECURITY_HEADERS.items():
        if header not in headers:
            findings.append({
                "check": f"Missing {header}",
                "severity": severity,
                "description": f"The response does not set the {header} header.",
            })

    for header in INFO_LEAK_HEADERS:
        if header in headers:
            value = headers[header]
            findings.append({
                "check": f"Information disclosure via {header}",
                "severity": classify_info_leak(value),
                "description": f"{header} header exposes: '{value}'.",
            })

    return {
        "target": host,
        "status": "up",
        "findings": findings,
        "error": None,
    }


if __name__ == "__main__":
    result = check_headers("http://localhost")
    print(result)
