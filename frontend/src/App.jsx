import { useMemo, useState } from "react";
import "./App.css";

const API_BASE = "http://localhost:3000/api/recon";

function priorityColor(priority) {
  if (priority === "high") return "badge high";
  if (priority === "medium") return "badge medium";
  return "badge low";
}

function App() {
  const [domain, setDomain] = useState("hackerone.com");
  const [scanId, setScanId] = useState("");
  const [status, setStatus] = useState("");
  const [statusMessage, setStatusMessage] = useState("");
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState("all");
  const [error, setError] = useState("");

  const filteredResults = useMemo(() => {
    if (filter === "all") return results;
    return results.filter((item) => item.priority === filter);
  }, [results, filter]);

  const summary = useMemo(() => {
    return {
      total: results.length,
      high: results.filter((r) => r.priority === "high").length,
      medium: results.filter((r) => r.priority === "medium").length,
      low: results.filter((r) => r.priority === "low").length,
    };
  }, [results]);

  const startDeepScan = async () => {
    setError("");
    setResults([]);
    setStatus("");
    setStatusMessage("");
    setScanId("");
    setLoading(true);

    try {
      const response = await fetch(`${API_BASE}/scan/deep`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ domain }),
      });

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error || "Failed to start scan");
      }

      setScanId(data.scanId);
      pollStatus(data.scanId);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };

  const pollStatus = async (id) => {
    const interval = setInterval(async () => {
      try {
        const response = await fetch(`${API_BASE}/status/${id}`);
        const data = await response.json();

        if (!data.success) {
          throw new Error(data.error || "Failed to fetch scan status");
        }

        setStatus(data.status);
        setStatusMessage(data.message || "");

        if (data.status === "completed") {
          clearInterval(interval);
          await fetchResults(id);
          setLoading(false);
        }

        if (data.status === "failed") {
          clearInterval(interval);
          setLoading(false);
          setError(data.message || "Scan failed");
        }
      } catch (err) {
        clearInterval(interval);
        setLoading(false);
        setError(err.message);
      }
    }, 3000);
  };

  const fetchResults = async (id) => {
    try {
      const response = await fetch(`${API_BASE}/results/${id}`);
      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error || "Failed to fetch results");
      }

      setResults(data.data || []);
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="app">
      <header className="hero">
        <h1>OSINT Bug Bounty Intelligence Platform</h1>
        <p>
          Live target scanning, prioritization, and attack surface triage for
          authorized reconnaissance workflows.
        </p>
      </header>

      <section className="panel">
        <div className="scan-form">
          <input
            type="text"
            placeholder="Enter root domain (e.g. hackerone.com)"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
          />
          <button onClick={startDeepScan} disabled={loading}>
            {loading ? "Scanning..." : "Run Deep Scan"}
          </button>
        </div>

        {scanId && (
          <div className="scan-meta">
            <p>
              <strong>Scan ID:</strong> {scanId}
            </p>
            <p>
              <strong>Status:</strong> {status || "queued"}
            </p>
            {statusMessage && (
              <p>
                <strong>Message:</strong> {statusMessage}
              </p>
            )}
          </div>
        )}

        {error && <div className="error-box">{error}</div>}
      </section>

      <section className="summary-grid">
        <div className="card">
          <h3>Total Assets</h3>
          <p>{summary.total}</p>
        </div>
        <div className="card">
          <h3>High Priority</h3>
          <p>{summary.high}</p>
        </div>
        <div className="card">
          <h3>Medium Priority</h3>
          <p>{summary.medium}</p>
        </div>
        <div className="card">
          <h3>Low Priority</h3>
          <p>{summary.low}</p>
        </div>
      </section>

      <section className="panel">
        <div className="toolbar">
          <h2>Findings</h2>
          <select value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="all">All</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Domain</th>
                <th>Status</th>
                <th>Priority</th>
                <th>Risk Score</th>
                <th>IP</th>
                <th>Ports</th>
                <th>Title</th>
                <th>Reasons</th>
              </tr>
            </thead>
            <tbody>
              {filteredResults.length === 0 ? (
                <tr>
                  <td colSpan="8" className="empty-cell">
                    No findings yet
                  </td>
                </tr>
              ) : (
                filteredResults.map((item, index) => (
                  <tr key={`${item.domain}-${index}`}>
                    <td>{item.domain}</td>
                    <td>{item.status || "-"}</td>
                    <td>
                      <span className={priorityColor(item.priority)}>
                        {item.priority}
                      </span>
                    </td>
                    <td>{item.risk_score}</td>
                    <td>{item.ip || "-"}</td>
                    <td>{item.ports?.length ? item.ports.join(", ") : "-"}</td>
                    <td>{item.title || "-"}</td>
                    <td>
                      <div className="reasons">
                        {(item.reasons || []).map((reason, i) => (
                          <span key={i} className="reason-pill">
                            {reason}
                          </span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export default App;
