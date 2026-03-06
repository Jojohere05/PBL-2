import React, { useState, useEffect } from 'react';
import { startScan, getScanStatus, getDashboardSummary, submitFeedback } from './api';
import { connectWebSocket, disconnectWebSocket } from './ws';
import './App.css';

function App() {
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [scanning, setScanning] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState('');
  const [findings, setFindings] = useState([]);
  const [summary, setSummary] = useState(null);
  const [dashboardData, setDashboardData] = useState(null);
  const [activeTab, setActiveTab] = useState('scan');
  const [error, setError] = useState(null);

  // Load dashboard data on mount
  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async () => {
    try {
      const data = await getDashboardSummary();
      setDashboardData(data);
    } catch (err) {
      console.error('Failed to load dashboard:', err);
    }
  };

  const handleStartScan = async () => {
    if (!repoUrl) {
      setError('Please enter a repository URL');
      return;
    }

    setError(null);
    setScanning(true);
    setFindings([]);
    setSummary(null);
    setProgress(0);

    try {
      const response = await startScan(repoUrl, branch);
      setScanId(response.scan_id);

      // Connect to WebSocket for real-time updates
      connectWebSocket(response.scan_id, {
        onProgress: (data) => {
          setProgress(data.progress);
          setStage(data.message);
        },
        onFinding: (data) => {
          setFindings(prev => [...prev, data.finding]);
        },
        onComplete: (data) => {
          setSummary(data.summary);
          setScanning(false);
          setProgress(100);
          loadDashboard();
        },
        onError: (err) => {
          setError(err.message || 'Scan failed');
          setScanning(false);
        }
      });
    } catch (err) {
      setError(err.message || 'Failed to start scan');
      setScanning(false);
    }
  };

  const handleFeedback = async (findingId, ruleId, feedbackType) => {
    try {
      await submitFeedback(findingId, ruleId, feedbackType);
      // Update finding in UI
      setFindings(prev => prev.map(f => 
        f.id === findingId ? { ...f, feedbackSubmitted: true } : f
      ));
    } catch (err) {
      console.error('Failed to submit feedback:', err);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: '#dc2626',
      high: '#ea580c',
      medium: '#ca8a04',
      low: '#65a30d'
    };
    return colors[severity] || '#6b7280';
  };

  const getSeverityEmoji = (severity) => {
    const emojis = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🟢'
    };
    return emojis[severity] || '⚪';
  };

  return (
    <div className="app">
      <header className="header">
        <h1>🔒 FinGuard</h1>
        <p>Security Scanning & Compliance</p>
      </header>

      <nav className="tabs">
        <button 
          className={activeTab === 'scan' ? 'active' : ''} 
          onClick={() => setActiveTab('scan')}
        >
          Scan
        </button>
        <button 
          className={activeTab === 'dashboard' ? 'active' : ''} 
          onClick={() => setActiveTab('dashboard')}
        >
          Dashboard
        </button>
        <button 
          className={activeTab === 'results' ? 'active' : ''} 
          onClick={() => setActiveTab('results')}
        >
          Results ({findings.length})
        </button>
      </nav>

      <main className="main">
        {activeTab === 'scan' && (
          <div className="scan-panel">
            <div className="form-group">
              <label>Repository URL</label>
              <input
                type="text"
                placeholder="https://github.com/owner/repo"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                disabled={scanning}
              />
            </div>

            <div className="form-group">
              <label>Branch</label>
              <input
                type="text"
                placeholder="main"
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
                disabled={scanning}
              />
            </div>

            <button 
              className="scan-button"
              onClick={handleStartScan}
              disabled={scanning}
            >
              {scanning ? 'Scanning...' : 'Start Scan'}
            </button>

            {error && (
              <div className="error-message">
                {error}
              </div>
            )}

            {scanning && (
              <div className="progress-section">
                <div className="progress-bar">
                  <div 
                    className="progress-fill" 
                    style={{ width: `${progress}%` }}
                  />
                </div>
                <p className="progress-text">{stage || 'Initializing...'}</p>
              </div>
            )}

            {summary && (
              <div className="summary-card">
                <h3>Scan Complete</h3>
                <div className="summary-grid">
                  <div className="summary-item critical">
                    <span className="count">{summary.by_severity?.critical || 0}</span>
                    <span className="label">Critical</span>
                  </div>
                  <div className="summary-item high">
                    <span className="count">{summary.by_severity?.high || 0}</span>
                    <span className="label">High</span>
                  </div>
                  <div className="summary-item medium">
                    <span className="count">{summary.by_severity?.medium || 0}</span>
                    <span className="label">Medium</span>
                  </div>
                  <div className="summary-item low">
                    <span className="count">{summary.by_severity?.low || 0}</span>
                    <span className="label">Low</span>
                  </div>
                </div>
                <div className="risk-score">
                  <span>Risk Score: </span>
                  <strong>{summary.risk_score || 0}/100</strong>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'dashboard' && (
          <div className="dashboard-panel">
            {dashboardData ? (
              <>
                <div className="stats-grid">
                  <div className="stat-card">
                    <h4>Total Scans</h4>
                    <span className="stat-value">{dashboardData.total_scans}</span>
                  </div>
                  <div className="stat-card">
                    <h4>Critical Findings</h4>
                    <span className="stat-value critical">{dashboardData.critical_findings}</span>
                  </div>
                  <div className="stat-card">
                    <h4>High Findings</h4>
                    <span className="stat-value high">{dashboardData.high_findings}</span>
                  </div>
                  <div className="stat-card">
                    <h4>Avg Risk Score</h4>
                    <span className="stat-value">{dashboardData.avg_risk_score?.toFixed(1) || 0}</span>
                  </div>
                </div>
              </>
            ) : (
              <p>Loading dashboard...</p>
            )}
          </div>
        )}

        {activeTab === 'results' && (
          <div className="results-panel">
            {findings.length === 0 ? (
              <p className="no-results">No findings yet. Run a scan to see results.</p>
            ) : (
              <div className="findings-list">
                {findings.map((finding, idx) => (
                  <div key={idx} className="finding-card">
                    <div className="finding-header">
                      <span className="severity-badge" style={{ backgroundColor: getSeverityColor(finding.severity) }}>
                        {getSeverityEmoji(finding.severity)} {finding.severity?.toUpperCase()}
                      </span>
                      <span className="rule-id">{finding.rule_id}</span>
                    </div>
                    <p className="finding-description">{finding.description}</p>
                    <div className="finding-location">
                      <code>{finding.file_path}</code>
                      {finding.line && <span> (line {finding.line})</span>}
                    </div>
                    <div className="finding-actions">
                      <button 
                        onClick={() => handleFeedback(idx, finding.rule_id, 'true_positive')}
                        disabled={finding.feedbackSubmitted}
                      >
                        ✓ Valid
                      </button>
                      <button 
                        onClick={() => handleFeedback(idx, finding.rule_id, 'false_positive')}
                        disabled={finding.feedbackSubmitted}
                      >
                        ✗ False Positive
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </main>

      <footer className="footer">
        <p>FinGuard Security Scanner v1.0.0</p>
      </footer>
    </div>
  );
}

export default App;
