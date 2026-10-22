/**
 * Automated Web Scanner - Client-Side Controller
 * Cybersecurity Mini Project
 */

document.addEventListener("DOMContentLoaded", () => {
  const scanForm = document.getElementById("scanForm");
  const urlInput = document.getElementById("urlInput");
  const scanBtn = document.getElementById("scanBtn");
  const loadingIndicator = document.getElementById("loadingIndicator");
  const alertBox = document.getElementById("alertBox");
  const alertTitle = document.getElementById("alertTitle");
  const alertMessage = document.getElementById("alertMessage");
  const resultsSection = document.getElementById("resultsSection");

  const downloadTxtBtn = document.getElementById("downloadTxtBtn");
  const downloadJsonBtn = document.getElementById("downloadJsonBtn");
  const sampleLinks = document.querySelectorAll(".sample-link");

  let latestScanData = null;
  let complianceChart = null;

  // Handle Quick Sample Target Clicks
  sampleLinks.forEach(link => {
    link.addEventListener("click", () => {
      urlInput.value = link.getAttribute("data-url");
      scanForm.dispatchEvent(new Event("submit"));
    });
  });

  // Handle Form Submission
  scanForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const rawUrl = urlInput.value.trim();

    if (!rawUrl) {
      showAlert("Input Required", "Please enter a valid website URL to scan.");
      return;
    }

    hideAlert();
    resultsSection.style.display = "none";
    loadingIndicator.style.display = "block";
    scanBtn.disabled = true;

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url: rawUrl })
      });

      const result = await response.json();

      if (!response.ok || !result.success) {
        const errorText = result.error || "Failed to scan website. Please verify the URL and network connectivity.";
        showAlert("Scan Failed", errorText);
      } else {
        latestScanData = result.data;
        renderResults(latestScanData);
        resultsSection.style.display = "block";
        resultsSection.scrollIntoView({ behavior: "smooth" });
      }
    } catch (err) {
      showAlert("Network Error", `Could not connect to the scanner service: ${err.message}`);
    } finally {
      loadingIndicator.style.display = "none";
      scanBtn.disabled = false;
    }
  });

  // Render Complete Scan Results
  function renderResults(data) {
    // 1. Stat cards
    document.getElementById("statTotalChecks").textContent = data.total_checks;
    document.getElementById("statHeadersPresent").textContent = data.headers_present;
    document.getElementById("statHeadersMissing").textContent = data.headers_missing;

    const httpsCard = document.getElementById("statHttpsCard");
    const statHttps = document.getElementById("statHttps");
    const statHttpsSub = document.getElementById("statHttpsSub");
    if (data.uses_https) {
      statHttps.textContent = "HTTPS (TLS)";
      statHttps.className = "stat-value text-green";
      statHttpsSub.textContent = "Encrypted Transport";
    } else {
      statHttps.textContent = "Plain HTTP";
      statHttps.className = "stat-value text-red";
      statHttpsSub.textContent = "Unencrypted (Risky)";
    }

    const statVerdict = document.getElementById("statVerdict");
    statVerdict.textContent = data.overall_status === "pass" ? "Passed" : (data.overall_status === "review" ? "Review" : "Hardening Needed");
    statVerdict.className = `stat-value ${data.overall_status === "pass" ? "text-green" : (data.overall_status === "review" ? "text-amber" : "text-red")}`;
    document.getElementById("statTime").textContent = `${data.server_info.response_time_ms} ms (${data.server_info.status_code})`;

    // 2. Render / Update Chart.js Donut
    renderComplianceChart(data.headers_present, data.headers_missing);

    // 3. Diagnostics
    document.getElementById("diagUrl").textContent = data.url;
    document.getElementById("diagFinalUrl").textContent = data.server_info.final_url;
    document.getElementById("diagStatus").textContent = `${data.server_info.status_code} (${data.server_info.redirect_count} redirect${data.server_info.redirect_count === 1 ? '' : 's'})`;
    document.getElementById("diagResponseTime").textContent = `${data.server_info.response_time_ms} ms`;
    document.getElementById("diagResolvedIp").textContent = data.server_info.resolved_ip;
    document.getElementById("diagContentType").textContent = data.server_info.content_type;
    document.getElementById("diagServer").textContent = data.server_info.server_header;

    document.getElementById("httpsExplanation").textContent = data.https_explanation;

    // 4. Security Headers Table
    const tbody = document.getElementById("headersTableBody");
    tbody.innerHTML = "";

    data.headers.forEach(h => {
      const tr = document.createElement("tr");

      const statusBadge = h.present
        ? `<span class="status-badge pass">PASS</span>`
        : `<span class="status-badge missing">MISSING</span>`;

      const detailContent = h.present
        ? `<div class="cell-value font-mono">${escapeHtml(h.value)}</div>`
        : `<div class="cell-rec">${escapeHtml(h.recommendation)}</div>`;

      tr.innerHTML = `
        <td class="font-mono font-medium">${escapeHtml(h.name)}</td>
        <td>${statusBadge}</td>
        <td>${detailContent}</td>
        <td class="cell-purpose">${escapeHtml(h.purpose)}</td>
      `;
      tbody.appendChild(tr);
    });

    // 5. Findings
    const findingsList = document.getElementById("findingsList");
    findingsList.innerHTML = "";
    if (data.findings && data.findings.length > 0) {
      data.findings.forEach(item => {
        const li = document.createElement("li");
        li.textContent = item;
        findingsList.appendChild(li);
      });
    } else {
      const li = document.createElement("li");
      li.textContent = "No urgent configuration deficiencies detected.";
      findingsList.appendChild(li);
    }

    // 6. Recommendations
    const recsList = document.getElementById("recommendationsList");
    recsList.innerHTML = "";
    if (data.recommendations && data.recommendations.length > 0) {
      data.recommendations.forEach(item => {
        const li = document.createElement("li");
        li.textContent = item;
        recsList.appendChild(li);
      });
    } else {
      const li = document.createElement("li");
      li.textContent = "All audited headers are present. Maintain periodic scanning to ensure continued compliance.";
      recsList.appendChild(li);
    }
  }

  // Render Chart.js Donut Chart
  function renderComplianceChart(present, missing) {
    const canvas = document.getElementById("headerComplianceChart");
    if (!canvas) return;

    if (complianceChart) {
      complianceChart.destroy();
    }

    if (typeof Chart === "undefined") {
      console.warn("Chart.js not loaded.");
      return;
    }

    const ctx = canvas.getContext("2d");
    complianceChart = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ["Headers Present", "Headers Missing"],
        datasets: [{
          data: [present, missing],
          backgroundColor: ["#10b981", "#ef4444"],
          borderColor: "#162032",
          borderWidth: 3,
          hoverOffset: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              color: "#94a3b8",
              font: {
                family: "'Plus Jakarta Sans', sans-serif",
                size: 11
              }
            }
          }
        },
        cutout: "68%"
      }
    });
  }

  // Handle Download TXT
  downloadTxtBtn.addEventListener("click", () => {
    if (!latestScanData) return;
    downloadReport("txt");
  });

  // Handle Download JSON
  downloadJsonBtn.addEventListener("click", () => {
    if (!latestScanData) return;
    downloadReport("json");
  });

  async function downloadReport(format) {
    try {
      const response = await fetch("/api/download-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          data: latestScanData,
          format: format
        })
      });

      if (!response.ok) {
        throw new Error("Server failed to generate report file.");
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const hostname = new URL(latestScanData.url).hostname || "target";
      a.download = `security_report_${hostname}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();
    } catch (err) {
      showAlert("Download Error", `Could not generate report: ${err.message}`);
    }
  }

  function showAlert(title, message) {
    alertTitle.textContent = title + ": ";
    alertMessage.textContent = message;
    alertBox.style.display = "block";
    alertBox.scrollIntoView({ behavior: "smooth" });
  }

  function hideAlert() {
    alertBox.style.display = "none";
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
