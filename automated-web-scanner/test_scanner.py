"""
Automated Web Scanner - Test Suite
Cybersecurity Mini Project

Covers all 8 required test scenarios using standard library unittest and unittest.mock:
1. Valid HTTPS URL
2. Valid HTTP URL
3. Invalid URL
4. Unreachable website
5. Connection timeout
6. Website with missing security headers
7. Redirect to a disallowed destination (SSRF via redirect)
8. Hostname that resolves to a private IP address (SSRF prevention)
"""

import unittest
from unittest.mock import patch, MagicMock
import socket

from scanner import (
    is_safe_ip,
    validate_and_resolve_url,
    scan_website,
    SSRFSecurityError,
    SECURITY_HEADERS
)


class TestAutomatedWebScanner(unittest.TestCase):

    # -------------------------------------------------------------
    # Test 1: Valid HTTPS URL
    # -------------------------------------------------------------
    @patch("scanner.validate_and_resolve_url")
    @patch("scanner.fetch_response")
    def test_01_valid_https_url(self, mock_fetch, mock_validate):
        """Test scanning a valid, reachable HTTPS website."""
        mock_validate.return_value = ("https://example.com", "example.com", ["93.184.216.34"])

        # Mock HTTP response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.is_redirect = False
        mock_response.url = "https://example.com"
        mock_response.headers = {
            "Content-Type": "text/html; charset=UTF-8",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "Server": "cloudflare"
        }
        mock_fetch.return_value = mock_response

        result = scan_website("https://example.com")

        self.assertTrue(result["uses_https"])
        self.assertEqual(result["https_status"], "pass")
        self.assertEqual(result["headers_present"], 6)
        self.assertEqual(result["headers_missing"], 0)
        self.assertEqual(result["server_info"]["status_code"], 200)
        self.assertIn("cloudflare", result["server_info"]["server_header"])

    # -------------------------------------------------------------
    # Test 2: Valid HTTP URL
    # -------------------------------------------------------------
    @patch("scanner.validate_and_resolve_url")
    @patch("scanner.fetch_response")
    def test_02_valid_http_url(self, mock_fetch, mock_validate):
        """Test scanning a plain HTTP URL."""
        mock_validate.return_value = ("http://example.com", "example.com", ["93.184.216.34"])

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.is_redirect = False
        mock_response.url = "http://example.com"
        mock_response.headers = {
            "Content-Type": "text/html",
            "X-Content-Type-Options": "nosniff"
        }
        mock_fetch.return_value = mock_response

        result = scan_website("http://example.com")

        self.assertFalse(result["uses_https"])
        self.assertEqual(result["https_status"], "warning")
        self.assertTrue(any("Insecure Transport" in f for f in result["findings"]))

    # -------------------------------------------------------------
    # Test 3: Invalid URL format
    # -------------------------------------------------------------
    def test_03_invalid_url_format(self):
        """Test that malformed or unsupported scheme URLs are rejected."""
        invalid_urls = [
            "",
            "ftp://files.example.com",
            "javascript:alert(1)",
            "data:text/html,test",
            "file:///etc/passwd",
            "://no-host",
            "http://"
        ]
        for url in invalid_urls:
            with self.assertRaises(ValueError):
                validate_and_resolve_url(url)

    # -------------------------------------------------------------
    # Test 4: Unreachable website (DNS failure)
    # -------------------------------------------------------------
    @patch("socket.getaddrinfo")
    def test_04_unreachable_website(self, mock_dns):
        """Test that non-existent domains raise ConnectionError gracefully."""
        mock_dns.side_effect = socket.gaierror(socket.EAI_NONAME, "Name or service not known")

        with self.assertRaises(ConnectionError) as ctx:
            scan_website("https://this-domain-definitely-does-not-exist-987654.com")
        self.assertIn("DNS resolution failed", str(ctx.exception))

    # -------------------------------------------------------------
    # Test 5: Connection timeout
    # -------------------------------------------------------------
    @patch("scanner.validate_and_resolve_url")
    @patch("scanner.fetch_response")
    def test_05_connection_timeout(self, mock_fetch, mock_validate):
        """Test that unresponsive servers trigger TimeoutError."""
        mock_validate.return_value = ("https://slow.example.com", "slow.example.com", ["93.184.216.34"])
        mock_fetch.side_effect = TimeoutError("Connection timed out")

        with self.assertRaises(TimeoutError) as ctx:
            scan_website("https://slow.example.com")
        self.assertIn("Connection Timed Out", str(ctx.exception))

    # -------------------------------------------------------------
    # Test 6: Website with missing security headers
    # -------------------------------------------------------------
    @patch("scanner.validate_and_resolve_url")
    @patch("scanner.fetch_response")
    def test_06_missing_security_headers(self, mock_fetch, mock_validate):
        """Test that missing headers are properly identified and recommended."""
        mock_validate.return_value = ("https://unhardened.example.com", "unhardened.example.com", ["93.184.216.34"])

        # Returns NO security headers
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.is_redirect = False
        mock_response.url = "https://unhardened.example.com"
        mock_response.headers = {
            "Content-Type": "text/html",
            "Server": "Apache/2.4.41"
        }
        mock_fetch.return_value = mock_response

        result = scan_website("https://unhardened.example.com")

        self.assertEqual(result["headers_present"], 0)
        self.assertEqual(result["headers_missing"], 6)
        self.assertEqual(result["overall_status"], "failed")

        # Verify all 6 missing headers are listed in recommendations
        for header_name in SECURITY_HEADERS.keys():
            self.assertTrue(
                any(header_name in rec for rec in result["recommendations"]),
                f"Missing recommendation for {header_name}"
            )

    # -------------------------------------------------------------
    # Test 7: Redirect to a disallowed destination (SSRF via redirect)
    # -------------------------------------------------------------
    @patch("scanner.fetch_response")
    def test_07_redirect_to_disallowed_destination(self, mock_fetch):
        """Test that redirects to internal IP or localhost are intercepted and blocked."""
        with patch("scanner.validate_and_resolve_url") as mock_validate:
            def validate_side_effect(url):
                if "127.0.0.1" in url or "localhost" in url:
                    raise SSRFSecurityError("Security Alert (SSRF Prevention): Restricted destination.")
                return url, "public-redirector.com", ["93.184.216.34"]

            mock_validate.side_effect = validate_side_effect

            mock_redirect_response = MagicMock()
            mock_redirect_response.status_code = 302
            mock_redirect_response.is_redirect = True
            mock_redirect_response.headers = {"Location": "http://127.0.0.1/admin"}
            mock_fetch.return_value = mock_redirect_response

            with self.assertRaises(SSRFSecurityError) as ctx:
                scan_website("https://public-redirector.com")
            self.assertIn("SSRF Prevention", str(ctx.exception))

    # -------------------------------------------------------------
    # Test 8: Hostname that resolves to a private IP (SSRF direct)
    # -------------------------------------------------------------
    def test_08_hostname_resolves_to_private_ip(self):
        """Test that hostnames pointing to private, loopback, or metadata IPs are blocked."""
        # Direct IP tests with is_safe_ip
        self.assertFalse(is_safe_ip("127.0.0.1"))
        self.assertFalse(is_safe_ip("10.0.0.1"))
        self.assertFalse(is_safe_ip("192.168.1.1"))
        self.assertFalse(is_safe_ip("172.16.0.5"))
        self.assertFalse(is_safe_ip("169.254.169.254")) # AWS/GCP metadata service
        self.assertFalse(is_safe_ip("::1"))
        self.assertFalse(is_safe_ip("0.0.0.0"))

        # Public IPs should pass
        self.assertTrue(is_safe_ip("8.8.8.8"))
        self.assertTrue(is_safe_ip("93.184.216.34"))
        self.assertTrue(is_safe_ip("1.1.1.1"))

        # Test validate_and_resolve_url on localhost
        with self.assertRaises(SSRFSecurityError):
            validate_and_resolve_url("http://localhost:8080")


if __name__ == "__main__":
    unittest.main(verbosity=2)
