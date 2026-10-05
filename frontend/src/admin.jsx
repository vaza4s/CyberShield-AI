import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { adminGet, adminLogin, API_BASE_URL } from "./api";
import { ArrowIcon, DatabaseIcon, FileIcon, LinkIcon, ShieldIcon, UserIcon } from "./icons";
import "./styles.css";
import "./admin.css";
import { ThemeControl, useThemePreference } from "./theme";

const TOKEN_KEY = "cybershield_admin_token";

function Brand() {
  return (
    <a className="brand" href="/">
      <span className="brand-mark"><ShieldIcon /></span>
      <span className="brand-name">CyberShield <em>AI</em></span>
    </a>
  );
}

function Login({ onAuthenticated, theme }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function submit(e) {
    e.preventDefault();
    setLoading(true); setError("");
    try {
      const data = await adminLogin(username, password);
      const token = data?.access_token || data?.token || data?.jwt || data?.accessToken;
      if (!token) throw new Error("Login succeeded, but no JWT token was returned.");
      sessionStorage.setItem(TOKEN_KEY, token);
      onAuthenticated(token);
    } catch (err) {
      setError(err?.message || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="admin-login-page">
      <div className="admin-login-theme"><ThemeControl {...theme} /></div>
      <div className="admin-login-card">
        <div className="admin-login-brand"><Brand /></div>
        <span className="admin-badge">Protected admin area</span>
        <h1>Security operations dashboard</h1>
        <p>Sign in with the admin credentials configured on the FastAPI backend. The credentials are never stored in this frontend.</p>
        <form onSubmit={submit}>
          <label>Username<input value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" required /></label>
          <label>Password<input type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="current-password" required /></label>
          {error && <div className="error-box">{error}</div>}
          <button className="btn btn-primary" type="submit" disabled={loading}><span>{loading ? "Signing in..." : "Sign in"}</span><ArrowIcon /></button>
        </form>
        <small className="admin-api-label">API: {API_BASE_URL}</small>
      </div>
    </main>
  );
}

function MetricCard({ title, value, icon: Icon, tone = "gold" }) {
  return (
    <article className="admin-metric glass-card">
      <span className={`admin-metric-icon ${tone}`}><Icon /></span>
      <div><small>{title}</small><strong>{value ?? "—"}</strong></div>
    </article>
  );
}

function findValue(obj, keys, fallback = "—") {
  for (const key of keys) {
    if (obj && obj[key] !== undefined && obj[key] !== null) return obj[key];
  }
  return fallback;
}

function normalizeRecent(data) {
  if (!data) return [];
  if (Array.isArray(data)) return data;
  for (const key of ["recent", "items", "records", "activity", "scans", "data"]) {
    if (Array.isArray(data[key])) return data[key];
  }
  const collected = [];
  const moduleLabels = { url_scans: "url", file_scans: "file", login_scans: "login", security_events: "security event" };
  for (const [key, value] of Object.entries(data)) {
    if (Array.isArray(value)) value.forEach(item => collected.push({ module: moduleLabels[key] || key, ...item }));
  }
  return collected;
}

function Dashboard({ token, onLogout, theme }) {
  const [stats, setStats] = useState(null);
  const [recent, setRecent] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function load() {
    setLoading(true); setError("");
    try {
      const [statsData, recentData] = await Promise.all([
        adminGet("/admin/stats", token),
        adminGet("/admin/recent", token)
      ]);
      setStats(statsData);
      setRecent(normalizeRecent(recentData));
    } catch (err) {
      if (/401|403|token|auth/i.test(String(err?.message))) {
        sessionStorage.removeItem(TOKEN_KEY);
        onLogout();
        return;
      }
      setError(err?.message || "Could not load admin data.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  const metrics = useMemo(() => [
    ["Total scans", stats?.overall?.total_scans ?? findValue(stats, ["total_scans", "total", "scans"]), DatabaseIcon, "blue"],
    ["URL scans", stats?.url_scanner?.total ?? findValue(stats, ["url_scans", "urls", "url_count"]), LinkIcon, "gold"],
    ["File scans", stats?.file_scanner?.total ?? findValue(stats, ["file_scans", "files", "file_count"]), FileIcon, "green"],
    ["Threats / high risk", stats?.overall?.confirmed_threats ?? findValue(stats, ["threats", "high_risk", "malicious", "threat_count"]), ShieldIcon, "rose"],
  ], [stats]);

  return (
    <div className="admin-shell">
      <header className="admin-topbar">
        <Brand />
        <div className="admin-top-actions">
          <ThemeControl {...theme} compact />
          <a href="/" className="admin-home-link">User site</a>
          <button type="button" onClick={load} disabled={loading}>Refresh</button>
          <button className="admin-logout" type="button" onClick={() => { sessionStorage.removeItem(TOKEN_KEY); onLogout(); }}>Logout</button>
        </div>
      </header>

      <main className="admin-main">
        <div className="admin-heading">
          <div><span className="admin-badge">Live monitoring</span><h1>Admin Dashboard</h1><p>Protected statistics and recent scan activity returned by the FastAPI admin endpoints.</p></div>
          <div className="admin-system"><span className="status-dot" /> API connected</div>
        </div>

        {error && <div className="error-box admin-error">{error}</div>}

        <section className="admin-metric-grid">
          {metrics.map(([title, value, Icon, tone]) => <MetricCard key={title} title={title} value={value} icon={Icon} tone={tone} />)}
        </section>

        <section className="admin-content-grid">
          <article className="admin-panel glass-card">
            <div className="admin-panel-head"><div><small>Activity feed</small><h2>Recent security events</h2></div><span>{recent.length} items</span></div>
            {loading ? (
              <div className="admin-loading">Loading protected data...</div>
            ) : recent.length === 0 ? (
              <div className="admin-empty">No recent activity returned by the API.</div>
            ) : (
              <div className="activity-list">
                {recent.slice(0, 30).map((item, index) => {
                  const moduleName = item.module || item.type || item.scan_type || item.category || "scan";
                  const target = item.url || item.filename || item.file_name || item.email || item.user_identifier || item.username || item.ip_address || item.target || "Security event";
                  const result = item.risk_level || item.prediction || item.status || item.result || "recorded";
                  const score = item.risk_score ?? item.score ?? item.confidence;
                  return (
                    <div className="activity-row" key={`${index}-${target}`}>
                      <span className="activity-icon"><ShieldIcon /></span>
                      <div className="activity-copy"><strong>{String(target).slice(0, 70)}</strong><small>{String(moduleName).replaceAll("_", " ")}</small></div>
                      <div className="activity-result"><b>{String(result)}</b>{score !== undefined && <small>{typeof score === "number" ? `${score <= 1 ? Math.round(score*100) : Math.round(score)}%` : score}</small>}</div>
                    </div>
                  );
                })}
              </div>
            )}
          </article>

          <aside className="admin-side">
            <article className="admin-panel glass-card">
              <div className="admin-panel-head"><div><small>Backend</small><h2>Security architecture</h2></div></div>
              <ul className="architecture-list">
                <li><span><LinkIcon /></span><div><strong>URL engine</strong><small>ML + security heuristics</small></div></li>
                <li><span><FileIcon /></span><div><strong>File scanner</strong><small>Static analysis only</small></div></li>
                <li><span><UserIcon /></span><div><strong>Login risk</strong><small>Transparent rule-based scoring</small></div></li>
                <li><span><ShieldIcon /></span><div><strong>Admin APIs</strong><small>Bearer JWT required</small></div></li>
              </ul>
            </article>
            <article className="admin-panel admin-note glass-card">
              <small>Project scope</small>
              <h2>Academic threat-assessment prototype</h2>
              <p>CyberShield is a decision-support system. The file scanner is static and does not replace antivirus or sandboxing.</p>
            </article>
          </aside>
        </section>
      </main>
    </div>
  );
}

function AdminApp() {
  const theme = useThemePreference();
  const [token, setToken] = useState(() => sessionStorage.getItem(TOKEN_KEY));
  return token
    ? <Dashboard token={token} onLogout={() => setToken(null)} theme={theme} />
    : <Login onAuthenticated={setToken} theme={theme} />;
}

createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <AdminApp />
  </React.StrictMode>
);
