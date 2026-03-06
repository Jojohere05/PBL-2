/**
 * API Client for FinGuard Backend
 */

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

/**
 * Generic fetch wrapper with error handling
 */
async function fetchApi(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  
  const defaultOptions = {
    headers: {
      'Content-Type': 'application/json',
    },
  };
  
  const response = await fetch(url, { ...defaultOptions, ...options });
  
  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Request failed' }));
    throw new Error(error.detail || error.message || `HTTP ${response.status}`);
  }
  
  return response.json();
}

// ============ Scan Endpoints ============

/**
 * Start a new security scan
 */
export async function startScan(repoUrl, branch = 'main', scanTypes = null) {
  return fetchApi('/scan/start', {
    method: 'POST',
    body: JSON.stringify({
      repo_url: repoUrl,
      branch: branch,
      scan_types: scanTypes || ['secrets', 'dependencies', 'terraform']
    })
  });
}

/**
 * Get status of a scan
 */
export async function getScanStatus(scanId) {
  return fetchApi(`/scan/status/${scanId}`);
}

/**
 * Get results of a completed scan
 */
export async function getScanResults(scanId) {
  return fetchApi(`/scan/results/${scanId}`);
}

/**
 * Cancel an ongoing scan
 */
export async function cancelScan(scanId) {
  return fetchApi(`/scan/cancel/${scanId}`, { method: 'POST' });
}

// ============ Dashboard Endpoints ============

/**
 * Get dashboard summary
 */
export async function getDashboardSummary() {
  return fetchApi('/dashboard/summary');
}

/**
 * Get security trends
 */
export async function getSecurityTrends(days = 30) {
  return fetchApi(`/dashboard/trends?days=${days}`);
}

/**
 * Get top vulnerabilities
 */
export async function getTopVulnerabilities(limit = 10) {
  return fetchApi(`/dashboard/top-vulnerabilities?limit=${limit}`);
}

/**
 * Get compliance status
 */
export async function getComplianceStatus() {
  return fetchApi('/dashboard/compliance-status');
}

/**
 * Get recent scans
 */
export async function getRecentScans(limit = 5) {
  return fetchApi(`/dashboard/recent-scans?limit=${limit}`);
}

// ============ Feedback Endpoints ============

/**
 * Submit feedback for a finding
 */
export async function submitFeedback(findingId, ruleId, feedbackType, comment = null) {
  return fetchApi('/feedback/submit', {
    method: 'POST',
    body: JSON.stringify({
      finding_id: findingId,
      rule_id: ruleId,
      feedback_type: feedbackType,
      comment: comment
    })
  });
}

/**
 * Get current rule weights
 */
export async function getRuleWeights() {
  return fetchApi('/feedback/weights');
}

/**
 * Get feedback statistics
 */
export async function getFeedbackStats() {
  return fetchApi('/feedback/stats');
}

// ============ Report Endpoints ============

/**
 * Generate PDF report for a scan
 */
export async function generateReport(scanId) {
  const url = `${API_BASE_URL}/report/generate/${scanId}`;
  const response = await fetch(url);
  
  if (!response.ok) {
    throw new Error('Failed to generate report');
  }
  
  return response.blob();
}

/**
 * Download report
 */
export async function downloadReport(scanId, format = 'pdf') {
  const blob = await generateReport(scanId);
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `finguard-report-${scanId}.${format}`;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
}

export default {
  startScan,
  getScanStatus,
  getScanResults,
  cancelScan,
  getDashboardSummary,
  getSecurityTrends,
  getTopVulnerabilities,
  getComplianceStatus,
  getRecentScans,
  submitFeedback,
  getRuleWeights,
  getFeedbackStats,
  generateReport,
  downloadReport
};
