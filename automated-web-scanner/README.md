# Automated Web Scanner — Cybersecurity Mini Project
**Website Security Configuration & HTTP Headers Audit Tool**

---

## 1. Abstract
The **Automated Web Scanner** is an educational, defensive cybersecurity web application developed using Python, Flask, HTML, CSS, JavaScript, and Chart.js. The tool audits target websites for critical HTTP security header configurations, verifies HTTPS encryption, inspects server response metrics, and enforces strict Server-Side Request Forgery (SSRF) countermeasures. The application categorizes results into clear, color-coded indicators, generates actionable hardening recommendations for web administrators, and exports audit findings in standardized TXT and JSON formats.

---

## 2. Problem Statement
Web application attacks such as Cross-Site Scripting (XSS), Clickjacking, MIME-confusion attacks, and Session Hijacking frequently succeed not due to complex zero-day exploits, but due to fundamental misconfigurations in HTTP response headers. Many developers and system administrators overlook standard security headers like `Content-Security-Policy` and `Strict-Transport-Security`. 

Existing enterprise vulnerability scanners are often expensive, complex for beginners to set up, or perform aggressive active vulnerability probes that can trigger intrusion prevention alerts. There is a need for a lightweight, beginner-friendly, and non-destructive defensive scanner that evaluates website configuration posture safely.

---

## 3. Objectives
1. Provide an intuitive web dashboard where users enter authorized URLs to evaluate security headers.
2. Inspect the 6 core HTTP security headers:
   - `Content-Security-Policy` (CSP)
   - `Strict-Transport-Security` (HSTS)
   - `X-Content-Type-Options`
   - `X-Frame-Options`
   - `Referrer-Policy`
   - `Permissions-Policy`
3. Verify transport layer security (HTTPS) and highlight risks associated with plain HTTP transmission.
4. Extract benign server diagnostics (HTTP status code, response time in ms, server header, MIME content type, final redirect target).
5. Defend the scanner itself against Server-Side Request Forgery (SSRF) by validating hostname resolution against private, loopback, and link-local IP addresses.
6. Provide clear, non-alarmist recommendations and downloadable TXT/JSON audit reports.

---

## 4. Existing System vs. Proposed System

| Feature / Aspect | Existing Enterprise Scanners | Proposed Automated Web Scanner |
| :--- | :--- | :--- |
| **Intrusiveness** | Active exploits, fuzzing, port scans, and high traffic | Purely defensive, passive HTTP header inspection (0 risk of denial of service) |
| **Complexity** | Complex CLI, heavy daemon setups, paid licensing | Lightweight Python + Flask stack, accessible web UI |
| **Educational Value** | Raw CVE numbers without conceptual context | Plain-English explanations of *why* each header matters and how to configure it |
| **Target Safety (SSRF)** | Often blindly attempts internal network probes if misconfigured | Built-in SSRF defense: blocks private IP ranges, loopbacks, and redirect hijacking |
| **Cost** | Commercial subscriptions ($1,000s/year) | 100% Free and Open Source using standard libraries |

---

## 5. Software and Hardware Requirements

### Software Requirements
- **Operating System:** Windows 10/11, macOS, or Linux (Ubuntu 20.04+)
- **Programming Language:** Python 3.8 to 3.12+
- **Web Framework:** Flask 3.0+
- **HTTP Client:** Python Requests 2.32+
- **Frontend Technologies:** HTML5, CSS3, Vanilla JavaScript (ES6+), Chart.js (via CDN)
- **Editor / IDE:** Visual Studio Code (VS Code)

### Hardware Requirements
- **Processor:** Intel Core i3 / AMD Ryzen 3 or higher
- **RAM:** 2 GB minimum (4 GB recommended)
- **Disk Space:** 200 MB free space for Python virtual environment and dependencies
- **Network Interface:** Active Internet connection for scanning external domains

---

## 6. System Architecture

```text
+-------------------------------------------------------------+
|                  Client Browser (Frontend)                  |
|  - HTML5 UI, CSS Dark Cybersecurity Theme                   |
|  - JavaScript Controller (Fetch API, DOM rendering)         |
|  - Chart.js Compliance Donut Visualization                  |
+------------------------------+------------------------------+
                               |
                        HTTP POST /api/scan
                        JSON { "url": "..." }
                               |
                               v
+-------------------------------------------------------------+
|                    Flask Backend (app.py)                   |
|  - Routes: /, /api/scan, /api/download-report               |
|  - Error Handlers & JSON Responses                          |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                 Scanner Engine (scanner.py)                 |
|                                                             |
|  1. URL Normalization & Scheme Validation                   |
|  2. DNS Resolution & SSRF Filter (is_safe_ip):              |
|     Blocks 127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16,         |
|     172.16.0.0/12, 169.254.0.0/16, ::1, etc.                |
|  3. Safe HTTP GET Request with Timeout & Stream Limits       |
|  4. Redirect Chain Tracking with Per-Hop SSRF Validation    |
|  5. 6-Header Analysis & Dictionary Matching                 |
|  6. HTTPS Verification & Summary Generation                 |
+------------------------------+------------------------------+
                               |
                        Outbound Probe
                               v
+-------------------------------------------------------------+
|                   Target Website Server                     |
|                   (e.g., https://example.com)               |
+-------------------------------------------------------------+
```

---

## 7. Module Descriptions

1. **`scanner.py` (Core Engine):**
   - `is_safe_ip(ip_str)`: Uses Python's `ipaddress` module to verify that resolved IPs do not belong to private, loopback, link-local, multicast, or reserved ranges.
   - `validate_and_resolve_url(raw_url)`: Parses target URL, validates scheme, resolves DNS via `socket.getaddrinfo`, and checks all resolved IPs.
   - `scan_website(raw_url)`: Manages outbound HTTP request session, measures round-trip latency, follows redirects safely, and inspects headers against `SECURITY_HEADERS`.

2. **`app.py` (Flask Web Controller):**
   - Provides HTTP endpoints for web page rendering (`/`), asynchronous scanning (`/api/scan`), and report export generation (`/api/download-report`).

3. **`templates/index.html` (View):**
   - Responsive user interface with cyber-styled input field, real-time loading feedback, stat cards, Chart.js canvas, and responsive tabular results.

4. **`static/style.css` (Presentation):**
   - Custom dark cybersecurity design system using slate neutrals, sky cyan accents, and accessible contrast colors for audit statuses.

5. **`static/script.js` (Client Controller):**
   - Intercepts form submissions, interacts with the Flask REST API via async/await `fetch`, dynamically updates DOM nodes, and generates Chart.js visualizations.

6. **`test_scanner.py` (Test Suite):**
   - Automated unit tests covering valid HTTPS/HTTP URLs, malformed inputs, timeouts, unreachable hosts, missing headers, redirect loops, and SSRF attacks.

---

## 8. Algorithm & Workflow

1. **Input Reception:** User submits target URL via the web UI.
2. **URL Validation:** Ensure protocol is `http://` or `https://` and hostname is syntactically valid.
3. **SSRF Pre-flight Check:**
   - Resolve hostname to all candidate IP addresses.
   - If any IP is private, loopback (`127.0.0.1`), link-local (`169.254.169.254`), or reserved, reject immediately with HTTP 403 `SSRFSecurityError`.
4. **Execution of HTTP Request:**
   - Issue GET request with `stream=True` and strict timeouts (connect: 3s, read: 5s).
   - If response is a redirect (301/302), parse `Location`, validate new destination IP against SSRF filters, and repeat up to 4 hops.
5. **Header Extraction:**
   - Extract response headers into case-insensitive dictionary.
   - For each of the 6 security headers, check presence, value, and assign status (`pass` or `missing`).
6. **HTTPS Assessment:**
   - Check if final destination protocol is `https://`.
7. **Report Compilation & JSON Output:**
   - Calculate summary counts, gather server diagnostics, generate concrete remediation tips, and return JSON payload to frontend.
8. **UI Rendering:**
   - Frontend populates summary cards, renders donut chart, fills results table, and enables TXT/JSON download.

---

## 9. Installation & Execution (Windows 10 & VS Code)

### Step 1: Open VS Code Terminal
Open VS Code in the project folder (`automated-web-scanner`). Open the integrated terminal (`Ctrl + ~`).

### Step 2: Create a Python Virtual Environment
```powershell
python -m venv venv
```

### Step 3: Activate Virtual Environment
```powershell
.\venv\Scripts\Activate.ps1
```
*(If PowerShell restricts execution, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` once).*

### Step 4: Install Dependencies
```powershell
pip install -r requirements.txt
```

### Step 5: Run Automated Unit Tests
```powershell
python test_scanner.py
```
*Expected: 8/8 tests pass successfully.*

### Step 6: Start the Flask Application
```powershell
python app.py
```

### Step 7: Access the Scanner in Your Browser
Open your browser and navigate to:
```text
http://127.0.0.1:5000
```

---

## 10. Sample Output (Summary)

```text
======================================================================
AUTOMATED WEB SCANNER — SECURITY CONFIGURATION REPORT
======================================================================
Target URL:         https://example.com
Scan Timestamp:     2026-10-22 12:45:10 UTC
HTTP Status Code:   200
Response Time:      142.3 ms
Resolved IP:        93.184.216.34
HTTPS Configured:   YES
Headers Present:    2 / 6
Headers Missing:    4 / 6
Overall Verdict:    Hardening Needed — Important Security Headers Missing
======================================================================

[ PASS ] Strict-Transport-Security
  Value: max-age=31536000
[ PASS ] X-Content-Type-Options
  Value: nosniff
[ MISSING ] Content-Security-Policy
  Recommendation: Define a Content-Security-Policy header.
[ MISSING ] X-Frame-Options
  Recommendation: Set X-Frame-Options: DENY or SAMEORIGIN.
[ MISSING ] Referrer-Policy
  Recommendation: Configure Referrer-Policy: strict-origin-when-cross-origin.
[ MISSING ] Permissions-Policy
  Recommendation: Set Permissions-Policy: camera=(), microphone=(), geolocation=().
```

---

## 11. Advantages and Limitations

### Advantages:
- **Zero Risk:** Non-destructive and safe; complies with ethical defensive testing.
- **SSRF Resilient:** Prevents attackers from abusing the scanner to explore internal clouds or localhost.
- **Actionable Guidance:** Directly displays configuration directives for Apache, Nginx, or application frameworks.
- **Exportable Reports:** One-click download of audit artifacts in JSON and TXT format.

### Limitations:
- Evaluates HTTP response headers only; does not analyze DOM/JavaScript for client-side DOM-XSS.
- Does not perform authentication-required scans behind login forms.
- Does not assess TLS cipher suite strength or SSL certificate expiration dates.

---

## 12. Future Enhancements
1. **SSL/TLS Deep Audit:** Add TLS version inspection (checking for deprecated TLS 1.0/1.1) and certificate expiration countdown.
2. **Cookie Security Scanner:** Check `Set-Cookie` flags (`Secure`, `HttpOnly`, `SameSite=Strict/Lax`).
3. **Database Integration:** SQLite history storage to track security improvements of scanned websites over time.
4. **PDF Audit Generation:** Styled executive PDF report exports with compliance charts.
5. **DNS & Subdomain Checks:** SPF, DKIM, and DMARC email authentication record validation.

---

## 13. Conclusion
The **Automated Web Scanner** successfully provides a robust, defensive cybersecurity tool for auditing website configuration postures. By combining a modern responsive dashboard with an SSRF-protected Python/Flask engine, it empowers developers and cybersecurity students to understand, audit, and remediate critical HTTP security header deficiencies.
