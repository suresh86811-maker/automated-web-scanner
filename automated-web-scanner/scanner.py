"""
Automated Web Scanner - Core Scanning Engine
Cybersecurity Mini Project

This module performs website security configuration checks with strict SSRF
(Server-Side Request Forgery) protection, timeout controls, and header analysis.
"""

import time
import socket
import ipaddress
from urllib.parse import urlparse, urljoin

try:
    import requests
except ImportError:
    requests = None
    import urllib.request
    import urllib.error
    import ssl


# List of the 6 key HTTP security headers analyzed in this mini project
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "purpose": "Prevents Cross-Site Scripting (XSS), clickjacking, and code injection by specifying trusted sources of scripts, styles, and media.",
        "recommendation": "Define a Content-Security-Policy header. Example: default-src 'self'; script-src 'self' https://trustedscripts.example.com;",
    },
    "Strict-Transport-Security": {
        "purpose": "Forces the browser to communicate exclusively over encrypted HTTPS connections, protecting against SSL-stripping and MITM attacks.",
        "recommendation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload on HTTPS websites.",
    },
    "X-Content-Type-Options": {
        "purpose": "Stops browsers from MIME-sniffing the response away from the declared content-type, defending against drive-by download attacks.",
        "recommendation": "Set X-Content-Type-Options: nosniff on all HTTP responses.",
    },
    "X-Frame-Options": {
        "purpose": "Prevents the web page from being rendered inside an iframe, defending against clickjacking attacks.",
        "recommendation": "Set X-Frame-Options: DENY or SAMEORIGIN (or use CSP frame-ancestors).",
    },
    "Referrer-Policy": {
        "purpose": "Controls how much referrer information (such as internal URLs or session IDs in query strings) is sent when navigating away from the page.",
        "recommendation": "Configure Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
    },
    "Permissions-Policy": {
        "purpose": "Restricts browser features and APIs (such as camera, microphone, geolocation, and payment) from unauthorized use.",
        "recommendation": "Set Permissions-Policy: camera=(), microphone=(), geolocation=() based on feature needs.",
    },
}

# Special IPv4 Carrier-Grade NAT network (RFC 6598)
CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


class SSRFSecurityError(Exception):
    """Raised when a requested URL resolves to an internal or restricted IP address."""
    pass


def is_safe_ip(ip_str: str) -> bool:
    """
    Validates whether an IP address is safe for outbound public requests.
    Blocks private, loopback, link-local, multicast, reserved, and CGNAT IP addresses.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    # Block IPv4 or IPv6 loopback (127.0.0.1, ::1)
    if ip_obj.is_loopback:
        return False

    # Block RFC 1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    if ip_obj.is_private:
        return False

    # Block Link-local (169.254.0.0/16, fe80::/10 - often used in cloud metadata services)
    if ip_obj.is_link_local:
        return False

    # Block Multicast (224.0.0.0/4, ff00::/8)
    if ip_obj.is_multicast:
        return False

    # Block Reserved or unspecified addresses (0.0.0.0)
    if ip_obj.is_reserved or ip_obj.is_unspecified:
        return False

    # Block Carrier-Grade NAT (100.64.0.0/10)
    if ip_obj.version == 4 and ip_obj in CGNAT_NETWORK:
        return False

    return True


def validate_and_resolve_url(target_url: str):
    """
    Validates the user input URL, parses scheme and hostname,
    resolves DNS, and verifies that resolved IP addresses are safe.
    Returns: (normalized_url, hostname, resolved_ips)
    """
    if not target_url or not isinstance(target_url, str):
        raise ValueError("URL cannot be empty.")

    target_url = target_url.strip()

    # Reject unsupported schemes early (e.g. javascript:, ftp:, data:, file:)
    if ":" in target_url:
        scheme_candidate = target_url.split(":", 1)[0].lower()
        if scheme_candidate.isalpha() and scheme_candidate not in ("http", "https"):
            raise ValueError(f"Invalid URL scheme '{scheme_candidate}'. Only http:// and https:// are permitted.")

    if not (target_url.startswith("http://") or target_url.startswith("https://")):
        if target_url.startswith("//"):
            target_url = "https:" + target_url
        else:
            target_url = "https://" + target_url

    parsed = urlparse(target_url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid URL scheme '{parsed.scheme}'. Only http:// and https:// are permitted.")

    hostname = parsed.hostname
    if not hostname or hostname.strip() == "":
        raise ValueError("Could not extract a valid hostname from the URL.")

    # Block common local naming schemes
    hostname_lower = hostname.lower()
    disallowed_suffixes = (".local", ".internal", ".lan", ".home", ".test", ".corp")
    if hostname_lower in ("localhost", "127.0.0.1", "::1") or any(hostname_lower.endswith(s) for s in disallowed_suffixes):
        raise SSRFSecurityError(f"Target '{hostname}' is restricted: Local and internal hostnames are prohibited.")

    # Resolve hostname via DNS
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ConnectionError(f"DNS resolution failed for '{hostname}': Hostname could not be found.") from e

    resolved_ips = []
    for info in addr_info:
        ip = info[4][0]
        if ip not in resolved_ips:
            resolved_ips.append(ip)

    if not resolved_ips:
        raise ConnectionError(f"No IP addresses found for hostname '{hostname}'.")

    # Verify every resolved IP against SSRF blocklist
    for ip in resolved_ips:
        if not is_safe_ip(ip):
            raise SSRFSecurityError(
                f"Security Alert (SSRF Prevention): The hostname '{hostname}' resolves to restricted IP '{ip}'. "
                f"Scanning internal, private, or loopback networks is strictly prohibited."
            )

    return target_url, hostname, resolved_ips


def fetch_response(target_url: str, headers: dict):
    """
    Performs outbound HTTP GET request using Requests library or standard library fallback.
    Stream=True and short timeouts ensure minimal resource usage.
    """
    if requests is not None:
        return requests.get(
            target_url,
            headers=headers,
            timeout=(3.0, 5.0),
            allow_redirects=False,
            verify=True,
            stream=True
        )
    else:
        req = urllib.request.Request(target_url, headers=headers)
        ctx = ssl.create_default_context()
        raw = urllib.request.urlopen(req, timeout=5.0, context=ctx)
        class SimpleResponse:
            def __init__(self, r):
                self.status_code = r.getcode()
                self.headers = dict(r.headers)
                self.url = r.geturl()
                self.is_redirect = False
            def close(self):
                pass
        return SimpleResponse(raw)


def scan_website(raw_url: str) -> dict:
    """
    Executes a security scan against the validated website URL.
    Enforces SSRF prevention on initial request and subsequent redirects.
    Audits the 6 HTTP security headers, checks HTTPS status, and calculates metrics.
    """
    # Step 1: Validate URL and check initial DNS resolution
    url, hostname, initial_ips = validate_and_resolve_url(raw_url)

    # Standard defensive security probe headers
    headers = {
        "User-Agent": "AutomatedWebScanner/1.0 (Cybersecurity Educational Mini Project; +Defensive Testing)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    current_url = url
    max_redirects = 4
    redirect_chain = []
    final_response = None
    total_elapsed_ms = 0.0

    try:
        for _ in range(max_redirects):
            # Revalidate destination for every hop (including redirects)
            validate_and_resolve_url(current_url)

            start_time = time.perf_counter()
            resp = fetch_response(current_url, headers)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            total_elapsed_ms += elapsed_ms

            if hasattr(resp, "close"):
                resp.close()

            redirect_chain.append(current_url)

            # Check for redirect status
            status_code = getattr(resp, "status_code", 200)
            is_redirect_flag = getattr(resp, "is_redirect", False)
            if is_redirect_flag is True or status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location") if hasattr(resp, "headers") and resp.headers else None
                if not location or not isinstance(location, str):
                    final_response = resp
                    break
                next_url = urljoin(current_url, location)
                current_url = next_url
            else:
                final_response = resp
                break
        else:
            final_response = resp

    except SSRFSecurityError:
        raise
    except ValueError:
        raise
    except Exception as err:
        err_type = type(err).__name__
        err_str = str(err)
        if "Timeout" in err_type or "timed out" in err_str.lower():
            raise TimeoutError(f"Connection Timed Out: The target server did not respond within 5 seconds. ({err})")
        if "SSLError" in err_type or "SSL" in err_str or "certificate" in err_str.lower():
            raise ConnectionError(f"HTTPS Certificate Error: The target server has an invalid or untrusted SSL/TLS certificate. ({err})")
        raise ConnectionError(f"Connection Failed: Could not reach target server. ({err})")

    # Step 2: Analyze HTTP Security Headers
    response_headers = getattr(final_response, "headers", {})
    header_results = []
    headers_present_count = 0
    headers_missing_count = 0

    for header_name, meta in SECURITY_HEADERS.items():
        # Case-insensitive header lookup
        header_val = None
        for key in response_headers:
            if key.lower() == header_name.lower():
                header_val = response_headers[key]
                break

        is_present = header_val is not None
        if is_present:
            headers_present_count += 1
            status = "pass"
            note = f"Header is present: '{header_val}'"
        else:
            headers_missing_count += 1
            status = "missing"
            note = "Header is missing from response."

        header_results.append({
            "name": header_name,
            "present": is_present,
            "value": header_val,
            "status": status,
            "purpose": meta["purpose"],
            "recommendation": meta["recommendation"],
            "note": note
        })

    # Step 3: HTTPS Analysis
    resp_url = getattr(final_response, "url", current_url) or current_url
    uses_https = resp_url.startswith("https://")
    https_status = "pass" if uses_https else "warning"
    https_explanation = (
        "The website uses HTTPS with an active TLS/SSL certificate. Data transmitted between the browser "
        "and server is encrypted, protecting against eavesdropping and tampering. Note: HTTPS secures "
        "the transport channel but does not protect against application-layer bugs."
        if uses_https else
        "The website communicates over unencrypted plain HTTP. Traffic is vulnerable to interception, "
        "Man-in-the-Middle (MITM) tampering, and credential sniffing on public networks."
    )

    # Step 4: Extract Server Information (Safe metadata only)
    raw_server = response_headers.get("Server", None)
    content_type = response_headers.get("Content-Type", "Not Specified")

    server_info = {
        "status_code": getattr(final_response, "status_code", 200),
        "response_time_ms": round(total_elapsed_ms, 2),
        "initial_url": url,
        "final_url": resp_url,
        "content_type": content_type,
        "server_header": raw_server if raw_server else "Not Disclosed (Good Security Practice)",
        "server_disclosed": bool(raw_server),
        "redirect_count": len(redirect_chain) - 1,
        "redirect_chain": redirect_chain,
        "resolved_ip": initial_ips[0] if initial_ips else "N/A"
    }

    # Step 5: Synthesize Security Findings & Recommendations
    findings = []
    recommendations = []

    if not uses_https:
        findings.append("Insecure Transport: The website serves content over unencrypted HTTP.")
        recommendations.append("Obtain an SSL/TLS certificate (e.g., via Let's Encrypt) and enforce HTTPS redirection.")

    if raw_server:
        findings.append(f"Server Information Disclosure: 'Server' header exposes software details ('{raw_server}').")
        recommendations.append("Suppress or sanitize the 'Server' header in your web server configuration (e.g. server_tokens off in Nginx).")

    for h in header_results:
        if not h["present"]:
            findings.append(f"Missing Header: {h['name']} is not configured.")
            recommendations.append(f"{h['name']}: {h['recommendation']}")

    # Total checks = 6 security headers + 1 HTTPS check + 1 Server banner check
    total_checks = len(SECURITY_HEADERS) + 2
    passed_count = headers_present_count + (1 if uses_https else 0) + (1 if not raw_server else 0)

    # Generate Overall Assessment summary
    if headers_missing_count == 0 and uses_https:
        summary_verdict = "Excellent Header Security Posture"
        overall_status = "pass"
    elif headers_present_count >= 3 and uses_https:
        summary_verdict = "Moderate Security Configuration — Key Headers Present"
        overall_status = "review"
    else:
        summary_verdict = "Hardening Needed — Important Security Headers Missing"
        overall_status = "failed"

    return {
        "url": url,
        "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "total_checks": total_checks,
        "passed_checks": passed_count,
        "headers_present": headers_present_count,
        "headers_missing": headers_missing_count,
        "uses_https": uses_https,
        "https_status": https_status,
        "https_explanation": https_explanation,
        "headers": header_results,
        "server_info": server_info,
        "findings": findings,
        "recommendations": recommendations,
        "summary_verdict": summary_verdict,
        "overall_status": overall_status,
        "disclaimer": "This tool performs basic defensive HTTP configuration analysis. It does NOT exploit systems, perform port scans, or replace comprehensive penetration testing."
    }
