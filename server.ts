/**
 * Express Server for Automated Web Scanner
 * Serves API routes with strict SSRF defense and mounts Vite in dev mode
 */

import express from 'express';
import { createServer as createViteServer } from 'vite';
import dns from 'dns';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const lookupPromise = promisify(dns.lookup);
const app = express();
const PORT = 3000;

app.use(express.json());

// List of the 6 key HTTP security headers
const SECURITY_HEADERS = {
  'Content-Security-Policy': {
    purpose: "Prevents Cross-Site Scripting (XSS), clickjacking, and code injection by specifying trusted sources of scripts, styles, and media.",
    recommendation: "Define a Content-Security-Policy header. Example: default-src 'self'; script-src 'self' https://trustedscripts.example.com;",
    apache: 'Header set Content-Security-Policy "default-src \'self\';"',
    nginx: 'add_header Content-Security-Policy "default-src \'self\';" always;'
  },
  'Strict-Transport-Security': {
    purpose: "Forces browsers to communicate exclusively over encrypted HTTPS connections, protecting against SSL-stripping and MITM attacks.",
    recommendation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload on HTTPS websites.",
    apache: 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
    nginx: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
  },
  'X-Content-Type-Options': {
    purpose: "Stops browsers from MIME-sniffing the response away from the declared content-type, defending against drive-by download attacks.",
    recommendation: "Set X-Content-Type-Options: nosniff on all HTTP responses.",
    apache: 'Header set X-Content-Type-Options "nosniff"',
    nginx: 'add_header X-Content-Type-Options "nosniff" always;'
  },
  'X-Frame-Options': {
    purpose: "Prevents the web page from being rendered inside an iframe, defending against clickjacking attacks.",
    recommendation: "Set X-Frame-Options: DENY or SAMEORIGIN (or use CSP frame-ancestors).",
    apache: 'Header always set X-Frame-Options "DENY"',
    nginx: 'add_header X-Frame-Options "DENY" always;'
  },
  'Referrer-Policy': {
    purpose: "Controls how much referrer information (internal URLs, query strings) is sent when navigating away from the page.",
    recommendation: "Configure Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
    apache: 'Header set Referrer-Policy "strict-origin-when-cross-origin"',
    nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;'
  },
  'Permissions-Policy': {
    purpose: "Restricts browser features and APIs (such as camera, microphone, geolocation, and payment) from unauthorized use.",
    recommendation: "Set Permissions-Policy: camera=(), microphone=(), geolocation=() based on feature needs.",
    apache: 'Header set Permissions-Policy "camera=(), microphone=(), geolocation=()"',
    nginx: 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;'
  }
};

/**
 * Validates if an IP address is safe from SSRF.
 * Blocks private, loopback, link-local, multicast, CGNAT, and broadcast addresses.
 */
function isSafeIp(ip: string): boolean {
  if (!ip) return false;

  // IPv4 Loopback
  if (ip === '127.0.0.1' || ip.startsWith('127.')) return false;
  // IPv6 Loopback
  if (ip === '::1' || ip === '::' || ip === '0:0:0:0:0:0:0:1') return false;
  // Unspecified
  if (ip === '0.0.0.0') return false;

  // RFC 1918 Private IPv4
  if (ip.startsWith('10.')) return false;
  if (ip.startsWith('192.168.')) return false;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)) return false;

  // Link-Local (Cloud Metadata 169.254.169.254)
  if (ip.startsWith('169.254.')) return false;
  // Carrier-Grade NAT 100.64.0.0/10
  if (/^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./.test(ip)) return false;

  // Multicast 224.0.0.0/4
  if (/^(22[4-9]|23[0-9])\./.test(ip)) return false;
  // Broadcast
  if (ip === '255.255.255.255') return false;

  // IPv6 private/unique local
  if (ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd') || ip.toLowerCase().startsWith('fe80:')) {
    return false;
  }

  return true;
}

/**
 * Validates URL and checks DNS resolution for SSRF.
 */
async function validateAndResolve(rawUrl: string): Promise<{ normalizedUrl: string; hostname: string; ip: string }> {
  let targetUrl = rawUrl.trim();

  // Reject invalid schemes early
  if (targetUrl.includes('://')) {
    const scheme = targetUrl.split('://')[0].toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') {
      throw new Error(`Invalid URL scheme '${scheme}'. Only http:// and https:// are permitted.`);
    }
  } else if (targetUrl.includes(':')) {
    const candidate = targetUrl.split(':')[0].toLowerCase();
    if (/^[a-z]+$/.test(candidate) && candidate !== 'http' && candidate !== 'https') {
      throw new Error(`Invalid URL scheme '${candidate}'. Only http:// and https:// are permitted.`);
    }
  }

  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }

  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    throw new Error('Malformed URL structure. Please enter a valid website address.');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Invalid protocol '${parsed.protocol}'. Only http: and https: are allowed.`);
  }

  const hostname = parsed.hostname;
  if (!hostname) {
    throw new Error('URL does not contain a valid hostname.');
  }

  // Block localhost and internal names
  const lowerHost = hostname.toLowerCase();
  const disallowedSuffixes = ['.local', '.internal', '.lan', '.home', '.test', '.corp', '.invalid', '.localhost'];
  if (lowerHost === 'localhost' || disallowedSuffixes.some(s => lowerHost.endsWith(s))) {
    throw new Error(`SSRF Prevention: Scanning local and internal domains ('${hostname}') is prohibited.`);
  }

  // If already an IP literal, validate directly
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':')) {
    if (!isSafeIp(hostname)) {
      throw new Error(`SSRF Prevention: Direct scanning of private/restricted IP '${hostname}' is prohibited.`);
    }
    return { normalizedUrl: targetUrl, hostname, ip: hostname };
  }

  // Resolve hostname via DNS
  let resolvedIp: string;
  try {
    const result = await lookupPromise(hostname);
    resolvedIp = result.address;
  } catch (dnsErr: any) {
    throw new Error(`DNS resolution failed for '${hostname}': Hostname could not be found.`);
  }

  if (!isSafeIp(resolvedIp)) {
    throw new Error(`SSRF Prevention: The hostname '${hostname}' resolves to restricted IP '${resolvedIp}'. Scanning internal networks is strictly prohibited.`);
  }

  return { normalizedUrl: targetUrl, hostname, ip: resolvedIp };
}

// Route: POST /api/scan
app.post('/api/scan', async (req, res) => {
  try {
    const rawUrl = req.body?.url;
    if (!rawUrl || typeof rawUrl !== 'string') {
      return res.status(400).json({ success: false, error: 'Please enter a target URL (e.g., https://example.com).' });
    }

    const { normalizedUrl, hostname, ip } = await validateAndResolve(rawUrl);

    // Follow redirects manually with SSRF checks per hop
    let currentUrl = normalizedUrl;
    let finalUrl = normalizedUrl;
    let finalHeaders: Record<string, string> = {};
    let finalStatus = 200;
    let redirectCount = 0;
    const maxRedirects = 4;
    const redirectChain: string[] = [];

    const startTime = performance.now();

    for (let i = 0; i < maxRedirects; i++) {
      redirectChain.push(currentUrl);
      const hopValidation = await validateAndResolve(currentUrl);

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);

      const response = await fetch(currentUrl, {
        method: 'GET',
        headers: {
          'User-Agent': 'AutomatedWebScanner/1.0 (Cybersecurity Educational Mini Project; +Defensive Testing)',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        },
        redirect: 'manual',
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      finalStatus = response.status;
      finalUrl = currentUrl;
      const headersMap: Record<string, string> = {};
      response.headers.forEach((val, key) => {
        headersMap[key.toLowerCase()] = val;
      });
      finalHeaders = headersMap;

      // Check redirect
      if (response.status >= 300 && response.status < 400 && response.headers.has('location')) {
        const loc = response.headers.get('location')!;
        const nextUrl = new URL(loc, currentUrl).toString();
        currentUrl = nextUrl;
        redirectCount++;
      } else {
        break;
      }
    }

    const totalElapsedMs = Math.round(performance.now() - startTime);

    // Analyze 6 Security Headers
    let headersPresentCount = 0;
    let headersMissingCount = 0;
    const headerResults = Object.entries(SECURITY_HEADERS).map(([headerName, meta]) => {
      const headerVal = finalHeaders[headerName.toLowerCase()];
      const isPresent = Boolean(headerVal);

      if (isPresent) {
        headersPresentCount++;
      } else {
        headersMissingCount++;
      }

      return {
        name: headerName,
        present: isPresent,
        value: headerVal || null,
        status: isPresent ? 'pass' : 'missing',
        purpose: meta.purpose,
        recommendation: meta.recommendation,
        apacheSnippet: meta.apache,
        nginxSnippet: meta.nginx,
        note: isPresent ? `Header observed: "${headerVal}"` : "Header is missing from response."
      };
    });

    const usesHttps = finalUrl.startsWith('https://');
    const rawServer = finalHeaders['server'] || null;
    const contentType = finalHeaders['content-type'] || 'Not Specified';

    const findings: string[] = [];
    const recommendations: string[] = [];

    if (!usesHttps) {
      findings.push("Insecure Transport: Website serves content over unencrypted plain HTTP.");
      recommendations.push("Enforce HTTPS across all pages and redirect HTTP traffic to HTTPS.");
    }

    if (rawServer) {
      findings.push(`Server Disclosure: The 'Server' header announces server software details ('${rawServer}').`);
      recommendations.push("Suppress or sanitize the 'Server' header to hinder automated banner-grabbing.");
    }

    headerResults.forEach(h => {
      if (!h.present) {
        findings.push(`Missing Header: ${h.name} is not present.`);
        recommendations.push(`${h.name}: ${h.recommendation}`);
      }
    });

    let overallStatus = 'pass';
    let summaryVerdict = 'Excellent Header Security Posture';
    if (headersMissingCount > 0 || !usesHttps) {
      if (headersPresentCount >= 3 && usesHttps) {
        overallStatus = 'review';
        summaryVerdict = 'Moderate Security Configuration — Key Headers Present';
      } else {
        overallStatus = 'failed';
        summaryVerdict = 'Hardening Needed — Important Security Headers Missing';
      }
    }

    const resultPayload = {
      url: normalizedUrl,
      scan_timestamp: new Date().toUTCString(),
      total_checks: Object.keys(SECURITY_HEADERS).length + 2,
      passed_checks: headersPresentCount + (usesHttps ? 1 : 0) + (!rawServer ? 1 : 0),
      headers_present: headersPresentCount,
      headers_missing: headersMissingCount,
      uses_https: usesHttps,
      https_status: usesHttps ? 'pass' : 'warning',
      https_explanation: usesHttps
        ? "The website uses HTTPS with an active TLS/SSL connection. Data transmitted between the browser and server is encrypted, protecting against eavesdropping and tampering."
        : "The website communicates over unencrypted plain HTTP. Traffic is vulnerable to interception, Man-in-the-Middle (MITM) tampering, and credential sniffing.",
      headers: headerResults,
      server_info: {
        status_code: finalStatus,
        response_time_ms: totalElapsedMs,
        initial_url: normalizedUrl,
        final_url: finalUrl,
        content_type: contentType,
        server_header: rawServer || 'Not Disclosed (Good Security Practice)',
        server_disclosed: Boolean(rawServer),
        redirect_count: redirectCount,
        redirect_chain: redirectChain,
        resolved_ip: ip
      },
      findings,
      recommendations,
      summary_verdict: summaryVerdict,
      overall_status: overallStatus,
      disclaimer: "This tool performs basic defensive HTTP configuration analysis. It does NOT exploit systems, perform port scans, or replace comprehensive penetration testing."
    };

    return res.json({ success: true, data: resultPayload });

  } catch (err: any) {
    const errorMsg = err.message || 'An unexpected error occurred during scan.';
    const isSsrf = errorMsg.includes('SSRF');
    const isTimeout = errorMsg.includes('abort') || errorMsg.includes('timeout');

    return res.status(isSsrf ? 403 : (isTimeout ? 504 : 400)).json({
      success: false,
      error_type: isSsrf ? 'SSRF_BLOCKED' : (isTimeout ? 'TIMEOUT' : 'SCAN_ERROR'),
      error: errorMsg
    });
  }
});

// Route: GET /api/files - returns standalone project files for the project explorer & downloader
app.get('/api/files', (req, res) => {
  try {
    const basePath = path.resolve(__dirname, 'automated-web-scanner');
    const fileList = [
      { name: 'app.py', path: 'app.py', type: 'python', desc: 'Flask web application controller and API endpoints' },
      { name: 'scanner.py', path: 'scanner.py', type: 'python', desc: 'Defensive scanning engine with SSRF prevention and header audits' },
      { name: 'test_scanner.py', path: 'test_scanner.py', type: 'python', desc: 'Automated test suite covering all 8 required validation scenarios' },
      { name: 'requirements.txt', path: 'requirements.txt', type: 'text', desc: 'Minimal Python dependencies (Flask, requests)' },
      { name: 'README.md', path: 'README.md', type: 'markdown', desc: 'Complete academic documentation, architecture, and setup instructions' },
      { name: 'templates/index.html', path: 'templates/index.html', type: 'html', desc: 'Dark cybersecurity theme HTML dashboard view' },
      { name: 'static/style.css', path: 'static/style.css', type: 'css', desc: 'Custom cybersecurity stylesheet with accessible contrast colors' },
      { name: 'static/script.js', path: 'static/script.js', type: 'javascript', desc: 'Frontend controller, Chart.js donut rendering, and report exports' }
    ];

    const filesWithContent = fileList.map(f => {
      const fullPath = path.join(basePath, f.path);
      const content = fs.existsSync(fullPath) ? fs.readFileSync(fullPath, 'utf-8') : '';
      return { ...f, content };
    });

    res.json({ success: true, files: filesWithContent });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

async function startServer() {
  const isProduction = process.env.NODE_ENV === 'production';

  if (!isProduction) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Automated Web Scanner server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
