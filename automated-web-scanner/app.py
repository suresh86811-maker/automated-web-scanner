"""
Automated Web Scanner - Flask Web Application
Cybersecurity Mini Project

Main application entry point. Serves the web interface and JSON API endpoints.
"""

from flask import Flask, render_template, request, jsonify, make_response
import json
from scanner import scan_website, SSRFSecurityError

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


@app.route("/")
def index():
    """Renders the main cybersecurity scanner dashboard."""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def run_scan():
    """
    API endpoint to scan a target URL.
    Validates the input, invokes the scanner engine, and returns findings.
    """
    try:
        data = request.get_json(silent=True) or {}
        raw_url = data.get("url", "").strip()

        if not raw_url:
            return jsonify({
                "success": False,
                "error": "Please provide a valid website URL to scan (e.g., https://example.com)."
            }), 400

        # Execute security header scan
        scan_results = scan_website(raw_url)

        return jsonify({
            "success": True,
            "data": scan_results
        }), 200

    except SSRFSecurityError as ssrf_err:
        # 403 Forbidden for internal/private destinations
        return jsonify({
            "success": False,
            "error_type": "SSRF_BLOCKED",
            "error": str(ssrf_err)
        }), 403

    except ValueError as val_err:
        return jsonify({
            "success": False,
            "error_type": "INVALID_INPUT",
            "error": str(val_err)
        }), 400

    except TimeoutError as timeout_err:
        return jsonify({
            "success": False,
            "error_type": "TIMEOUT",
            "error": str(timeout_err)
        }), 504

    except ConnectionError as conn_err:
        return jsonify({
            "success": False,
            "error_type": "CONNECTION_FAILED",
            "error": str(conn_err)
        }), 502

    except Exception as e:
        return jsonify({
            "success": False,
            "error_type": "SERVER_ERROR",
            "error": f"An unexpected error occurred during scan: {str(e)}"
        }), 500


@app.route("/api/download-report", methods=["POST"])
def download_report():
    """
    Generates a downloadable TXT or JSON security report from scan results.
    """
    try:
        payload = request.get_json() or {}
        report_data = payload.get("data", {})
        report_format = payload.get("format", "txt").lower()

        if not report_data:
            return jsonify({"error": "No scan data provided to generate report."}), 400

        url = report_data.get("url", "website")
        safe_filename = url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")

        if report_format == "json":
            json_str = json.dumps(report_data, indent=2)
            response = make_response(json_str)
            response.headers["Content-Disposition"] = f"attachment; filename=security_report_{safe_filename}.json"
            response.headers["Content-Type"] = "application/json"
            return response
        else:
            # Format clean TXT report
            txt_lines = [
                "=" * 70,
                "AUTOMATED WEB SCANNER — SECURITY CONFIGURATION REPORT",
                "Cybersecurity Mini Project | Defensive Audit",
                "=" * 70,
                f"Target URL:         {report_data.get('url')}",
                f"Scan Timestamp:     {report_data.get('scan_timestamp')}",
                f"Final Destination:  {report_data.get('server_info', {}).get('final_url')}",
                f"HTTP Status Code:   {report_data.get('server_info', {}).get('status_code')}",
                f"Response Time:      {report_data.get('server_info', {}).get('response_time_ms')} ms",
                f"Resolved IP:        {report_data.get('server_info', {}).get('resolved_ip')}",
                f"Server Header:      {report_data.get('server_info', {}).get('server_header')}",
                "-" * 70,
                f"HTTPS Configured:   {'YES' if report_data.get('uses_https') else 'NO'}",
                f"Headers Present:    {report_data.get('headers_present')} / 6",
                f"Headers Missing:    {report_data.get('headers_missing')} / 6",
                f"Overall Verdict:    {report_data.get('summary_verdict')}",
                "=" * 70,
                "",
                "HTTP SECURITY HEADERS BREAKDOWN:",
                "-" * 70
            ]

            for h in report_data.get("headers", []):
                status_symbol = "[ PASS ]" if h.get("present") else "[ MISSING ]"
                txt_lines.append(f"{status_symbol} {h.get('name')}")
                if h.get("present"):
                    txt_lines.append(f"  Value: {h.get('value')}")
                else:
                    txt_lines.append(f"  Recommendation: {h.get('recommendation')}")
                txt_lines.append(f"  Security Purpose: {h.get('purpose')}")
                txt_lines.append("")

            txt_lines.append("=" * 70)
            txt_lines.append("SUMMARY OF FINDINGS:")
            txt_lines.append("-" * 70)
            for f in report_data.get("findings", []):
                txt_lines.append(f"• {f}")

            txt_lines.append("")
            txt_lines.append("RECOMMENDED REMEDIATION ACTIONS:")
            txt_lines.append("-" * 70)
            for r in report_data.get("recommendations", []):
                txt_lines.append(f"• {r}")

            txt_lines.append("")
            txt_lines.append("=" * 70)
            txt_lines.append("DISCLAIMER:")
            txt_lines.append(report_data.get("disclaimer", "Defensive educational testing only."))
            txt_lines.append("=" * 70)

            response = make_response("\n".join(txt_lines))
            response.headers["Content-Disposition"] = f"attachment; filename=security_report_{safe_filename}.txt"
            response.headers["Content-Type"] = "text/plain; charset=utf-8"
            return response

    except Exception as e:
        return jsonify({"error": f"Failed to generate report: {str(e)}"}), 500


if __name__ == "__main__":
    # Run development server on port 5000
    print("Starting Automated Web Scanner on http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=True)
