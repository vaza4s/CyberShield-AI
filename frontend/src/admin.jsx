import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { adminGet, adminLogin, API_BASE_URL } from "./api";
import { ArrowIcon, DatabaseIcon, FileIcon, LinkIcon, UserIcon } from "./icons";
import "./styles.css";
import "./admin.css";

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.getRegistrations()
    .then((registrations) => {
      registrations.forEach((registration) => registration.unregister());
    })
    .catch(() => {});
}

const TOKEN_KEY = "cybershield_admin_token";
const BRAND_ASSET = "/assets/cybershield-brand.svg";

function Brand() {
  return (
    <a className="csa-brand" href="/">
      <img src={BRAND_ASSET} alt="" />
      <span>
        <div><strong>CyberShield</strong><b>AI</b></div>
        <small>Detect&nbsp;&nbsp; • &nbsp;&nbsp;Prevent&nbsp;&nbsp; • &nbsp;&nbsp;Stay Safe</small>
      </span>
    </a>
  );
}

function Login({ onAuthenticated }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      const data = await adminLogin(username, password);
      const token = data?.access_token || data?.token || data?.jwt || data?.accessToken;
      if (!token) throw new Error("No access token returned by the backend.");
      sessionStorage.setItem(TOKEN_KEY, token);
      onAuthenticated(token);
    } catch (err) {
      setError(err?.message || "Sign in failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="csa-login">
      <div className="csa-login-ambient ambient-blue" />
      <div className="csa-login-ambient ambient-purple" />
      <header className="csa-login-head">
        <Brand />
        <span>PROTECTED ADMIN</span>
      </header>

      <section className="csa-login-card">
        <span className="csa-badge cyan">SECURE ACCESS</span>
        <h1>Security operations dashboard</h1>
        <p>Sign in with the admin credentials configured on the FastAPI backend. Your credentials stay inside this secure session.</p>

        <form onSubmit={submit}>
          <label>Username<input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" placeholder="admin" required /></label>
          <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" placeholder="••••••••••••" required /></label>
          {error && <div className="csa-error">{error}</div>}
          <button className="csa-signin" type="submit" disabled={loading}>
            <span>{loading ? "Signing in…" : "Sign in"}</span><ArrowIcon />
          </button>
        </form>

        <div className="csa-rule" />
        <div className="csa-api-status"><i /><span>API endpoint • {API_BASE_URL.replace(/^https?:\/\//, "")}</span></div>
        <small>JWT session • credentials are never stored in the frontend</small>
      </section>
    </main>
  );
}

function pick(obj, paths, fallback = "—") {
  for (const path of paths) {
    const value = path.split(".").reduce((acc, key) => acc?.[key], obj);
    if (value !== undefined && value !== null && value !== "") return value;
  }
  return fallback;
}

function metricRows(stats) {
  return [
    ["Total scans", pick(stats, ["overall.total_scans", "total_scans", "total", "scans"]), "blue"],
    ["URL scans", pick(stats, ["url_scanner.total", "url_scans", "urls"]), "cyan"],
    ["File scans", pick(stats, ["file_scanner.total", "file_scans", "files"]), "purple"],
    ["Threats / high risk", pick(stats, ["overall.confirmed_threats", "threats", "high_risk", "malicious"]), "pink"]
  ];
}

function normalizeRecent(data) {
  if (!data) return [];
  if (Array.isArray(data)) return data;
  for (const key of ["recent", "items", "records", "activity", "scans", "data"]) {
    if (Array.isArray(data[key])) return data[key];
  }
  const collected = [];
  const labels = { url_scans: "URL scan", file_scans: "File scan", login_scans: "Login risk", security_events: "Security event" };
  for (const [key, value] of Object.entries(data)) {
    if (Array.isArray(value)) value.forEach((item) => collected.push({ module: labels[key] || key, ...item }));
  }
  return collected;
}

function riskTone(value) {
  const text = String(value || "").toLowerCase();
  if (/malicious|high|critical|danger|threat/.test(text)) return "pink";
  if (/review|medium|warn|suspicious/.test(text)) return "orange";
  return "green";
}

function Dashboard({ token, onLogout }) {
  const [stats, setStats] = useState(null);
  const [recent, setRecent] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const [statsData, recentData] = await Promise.all([
        adminGet("/admin/stats", token),
        adminGet("/admin/recent", token)
      ]);
      setStats(statsData);
      setRecent(normalizeRecent(recentData));
    } catch (err) {
      const message = err?.message || "Could not load admin data.";
      if (/401|403|token|auth/i.test(message)) {
        sessionStorage.removeItem(TOKEN_KEY);
        onLogout();
        return;
      }
      setError(message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  const metrics = useMemo(() => metricRows(stats), [stats]);

  return (
    <div className="csa-dashboard">
      <div className="csa-dashboard-ambient" />
      <header className="csa-topbar">
        <Brand />
        <div className="csa-top-actions">
          <span className="csa-badge green">API CONNECTED</span>
          <a href="/">User Site <b>›</b></a>
          <button onClick={load} disabled={loading}>Refresh <b>›</b></button>
          <button className="logout" onClick={() => { sessionStorage.removeItem(TOKEN_KEY); onLogout(); }}>Logout <b>›</b></button>
        </div>
      </header>

      <main className="csa-main">
        <section className="csa-heading">
          <div><span>LIVE MONITORING</span><h1>Admin Dashboard</h1><p>Protected statistics and recent scan activity from the FastAPI admin endpoints.</p></div>
          <span className="csa-badge green health">SYSTEM HEALTHY</span>
        </section>

        {error && <div className="csa-error dashboard-error">{error}</div>}

        <section className="csa-metrics">
          {metrics.map(([title, value, tone]) => (
            <article className={`csa-metric ${tone}`} key={title}>
              <i /><div><small>{title}</small><strong>{value}</strong></div><span>{tone === "pink" ? "Needs attention" : "Live data"}</span>
            </article>
          ))}
        </section>

        <section className="csa-content">
          <article className="csa-feed">
            <div className="csa-panel-title"><div><span>ACTIVITY FEED</span><h2>Recent security events</h2></div><b>{recent.length} ITEMS</b></div>
            <div className="csa-feed-rule" />
            {loading ? (
              <div className="csa-empty">Loading protected activity…</div>
            ) : recent.length === 0 ? (
              <div className="csa-empty">No recent activity returned by the backend.</div>
            ) : (
              <div className="csa-feed-list">
                {recent.slice(0, 5).map((item, index) => {
                  const target = item.url || item.filename || item.file_name || item.email || item.user_identifier || item.username || item.ip_address || item.target || "Security event";
                  const module = item.module || item.type || item.scan_type || item.category || "Scan";
                  const status = item.risk_level || item.prediction || item.status || item.result || "Recorded";
                  const tone = riskTone(status);
                  return (
                    <div className="csa-feed-row" key={`${index}-${target}`}>
                      <i className={tone} />
                      <div><strong>{String(target).slice(0, 68)}</strong><small>{String(module).replaceAll("_", " ")}</small></div>
                      <span className={tone}>{String(status)}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </article>

          <aside className="csa-side">
            <article className="csa-architecture">
              <span>BACKEND</span>
              <h2>Security architecture</h2>
              {[
                [LinkIcon, "URL engine", "ML + security heuristics", "cyan"],
                [FileIcon, "File scanner", "Static analysis only", "purple"],
                [UserIcon, "Login risk", "Transparent rule scoring", "orange"],
                [DatabaseIcon, "Admin APIs", "Bearer JWT required", "green"]
              ].map(([Icon, title, meta, tone]) => (
                <div className="csa-arch-row" key={title}><i className={tone}><Icon /></i><div><strong>{title}</strong><small>{meta}</small></div></div>
              ))}
            </article>

            <article className="csa-scope">
              <span>PROJECT SCOPE</span>
              <h2>Academic threat-assessment prototype</h2>
              <p>CyberShield is a decision-support system. Static file analysis does not replace antivirus or sandboxing.</p>
            </article>
          </aside>
        </section>
      </main>
    </div>
  );
}

function AdminApp() {
  const [token, setToken] = useState(() => sessionStorage.getItem(TOKEN_KEY));
  return token ? <Dashboard token={token} onLogout={() => setToken(null)} /> : <Login onAuthenticated={setToken} />;
}

createRoot(document.getElementById("root")).render(
  <React.StrictMode><AdminApp /></React.StrictMode>
);
