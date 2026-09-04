"""
SSL/TLS Check Module
Connects to a target host on a given HTTPS port and inspects its
certificate for validity: whether it is trusted, expired, and how
close it is to expiry. Findings are returned with a severity rating.
"""

import ssl
import socket
import datetime

from cryptography import x509

from scanner.port_scanner import resolve_target, is_safe_target

# Certificate expiry thresholds, in days.
EXPIRY_WARNING_DAYS = 30


def check_ssl(raw_target: str, port: int = 443) -> dict:
    """Connect to the target on the given port and validate its SSL/TLS
    certificate. Returns a dictionary containing target, status,
    findings (list of dicts with check/severity/description), and
    error."""
    host = resolve_target(raw_target)

    if not is_safe_target(host):
        return {
            "target": host,
            "status": "error",
            "findings": [],
            "error": f"'{host}' is not a permitted scan target.",
        }

    findings = []

    # First attempt: a strict connection that verifies the certificate
    # against trusted certificate authorities. If this fails, it tells
    # us the cert is untrusted (self-signed, expired, wrong hostname,
    # or otherwise invalid).
    strict_context = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with strict_context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as e:
        findings.append({
            "check": "Certificate trust",
            "severity": "high",
            "description": f"Certificate is not trusted by a public CA: {e.reason}",
        })
        cert_der = _get_cert_der_untrusted(host, port)
    except (ssl.SSLError, socket.error) as e:
        return {
            "target": host,
            "status": "error",
            "findings": [],
            "error": f"Could not establish SSL connection: {e}",
        }
    else:
        findings.append({
            "check": "Certificate trust",
            "severity": "info",
            "description": "Certificate is trusted by a public CA.",
        })

    if cert_der:
        expiry_findings = _check_expiry(cert_der)
        findings.extend(expiry_findings)

    return {
        "target": host,
        "status": "up",
        "findings": findings,
        "error": None,
    }


def _get_cert_der_untrusted(host: str, port: int):
    """Retrieve the raw certificate bytes without validating trust,
    used only after trust validation has already failed, so expiry
    can still be checked and reported."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert(binary_form=True)
    except (ssl.SSLError, socket.error):
        return None


def _check_expiry(cert_der: bytes) -> list:
    """Parse the certificate's expiry date and return a finding
    reflecting whether it has expired, is expiring soon, or is valid
    well into the future."""
    findings = []
    certificate = x509.load_der_x509_certificate(cert_der)
    expiry_date = certificate.not_valid_after_utc
    days_remaining = (expiry_date - datetime.datetime.now(datetime.timezone.utc)).days

    if days_remaining < 0:
        findings.append({
            "check": "Certificate expiry",
            "severity": "high",
            "description": f"Certificate expired {abs(days_remaining)} day(s) ago.",
        })
    elif days_remaining <= EXPIRY_WARNING_DAYS:
        findings.append({
            "check": "Certificate expiry",
            "severity": "medium",
            "description": f"Certificate expires in {days_remaining} day(s).",
        })
    else:
        findings.append({
            "check": "Certificate expiry",
            "severity": "info",
            "description": f"Certificate is valid for {days_remaining} more day(s).",
        })

    return findings


if __name__ == "__main__":
    result = check_ssl("localhost", port=4443)
    print(result)
