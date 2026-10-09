import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { adminGet, adminLogin, API_BASE_URL } from "./api";
import { ArrowIcon, DatabaseIcon, FileIcon, LinkIcon, ShieldIcon, UserIcon } from "./icons";
import "./styles.css";
import "./admin.css";

const TOKEN_KEY = "cybershield_admin_token";

function BrandMark({ className = "" }) {
  return (
    <svg className={className} viewBox="0 0 48 48" fill="none" aria-hidden="true">
      <path d="M24 4.5 39.5 10.8v11.8c0 9.5-5.9 17-15.5 21.4C14.4 39.6 8.5 32.1 8.5 22.6V10.8L24 4.5Z" stroke="currentColor" strokeWidth="2" />
      <path d="M31.8 16.6c-1.9-2.1-4.5-3.2-7.5-3.2-6.2 0-10.7 4.5-10.7 10.6s4.5 10.6 10.7 10.6c3.1 0 5.7-1.1 7.6-3.3" stroke="var(--cs-accent)" strokeWidth="3.2" strokeLinecap="round" />
      <path d="m30.9 20.1 4.5 3.9-4.5 3.9" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function Brand() {
  return (
    <a className="adv-brand" href="/">
      <BrandMark />
      <span><strong>CyberShield</strong><small>SECURITY CONSOLE</small></span>
    </a>
  );
}

function LiquidSubmit({ loading }) {
  const ref = useRef(null);
  function move(e) {
    const r = ref.current?.getBoundingClientRect();
    if (!r || !ref.current) return;
    const x = (e.clientX - r.left) / r.width - 0.5;
    const y = (e.clientY - r.top) / r.height - 0.5;
    ref.current.style.setProperty("--ax", `${x * 34}px`);
    ref.current.style.setProperty("--ay", `${y * 20}px`);
  }
  return (
    <button ref={ref} className="adv-liquid" type="submit" disabled={loading} onPointerMove={move} onPointerLeave={() => { if (ref.current) { ref.current.style.setProperty("--ax", "0px"); ref.current.style.setProperty("--ay", "0px"); } }}>
      <i className="adv-liquid-a" /><i className="adv-liquid-b" /><i className="adv-liquid-shine" />
      <span>{loading ? "Signing in..." : "Sign in"}</span><ArrowIcon />
    </button>
  );
}

function Login({ onAuthenticated }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function submit(e) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const data = await adminLogin(username, password);
      const token = data?.access_token || data?.token || data?.jwt || data?.accessToken;
      if (!token) throw new Error("Login succeeded, but no access token was returned.");
      sessionStorage.setItem(TOKEN_KEY, token);
      onAuthenticated(token);
    } catch (err) {
      setError(err?.message || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="adv-login-page">
      <div className="adv-flow adv-flow-a" />
      <div className="adv-flow adv-flow-b" />
      <header className="adv-login-head"><Brand /><span>ADMIN ACCESS</span></header>

      <section className="adv-login-card">
        <span className="adv-eyebrow-pill">SECURE SESSION</span>
        <h1>Security operations<br />dashboard</h1>
        <p>Authenticate to access protected scan statistics, incidents, and recent security activity.</p>
        <form onSubmit={submit}>
          <label>Username<input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required placeholder="admin" /></label>
          <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required placeholder="••••••••••••" /></label>
          {error && <div className="adv-error">{error}</div>}
          <LiquidSubmit loading={loading} />
        </form>
        <div className="adv-login-rule" />
        <div className="adv-api"><i /><span>FastAPI connected • {API_BASE_URL.replace(/^https?:\/\//, "")}</span></div>
        <small>JWT session • credentials stay in this secure browser session</small>
      </section>
    </main>
  );
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

function pick(obj, keys, fallback = "—") {
  for (const key of keys) if (obj?.[key] !== undefined && obj?.[key] !== null) return obj[key];
  return fallback;
}

function metricData(stats) {
  return [
    ["Total scans", stats?.overall?.total_scans ?? pick(stats, ["total_scans", "total", "scans"]), "blue"],
    ["URL scans", stats?.url_scanner?.total ?? pick(stats, ["url_scans", "urls", "url_count"]), "cyan"],
    ["File scans", stats?.file_scanner?.total ?? pick(stats, ["file_scans", "files", "file_count"]), "indigo"],
    ["Threats", stats?.overall?.confirmed_threats ?? pick(stats, ["threats", "high_risk", "malicious", "threat_count"]), "red"]
  ];
}

function eventTone(value) {
  const s = String(value || "").toLowerCase();
  if (/malicious|high|critical|danger|threat/.test(s)) return "red";
  if (/medium|review|warn|suspicious/.test(s)) return "orange";
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

  const metrics = useMemo(() => metricData(stats), [stats]);

  return (
    <div className="adv-admin">
      <header className="adv-admin-top">
        <Brand />
        <div className="adv-admin-actions">
          <span className="adv-online"><i />LOCAL ENGINE</span>
          <a href="/">User site</a>
          <button onClick={load} disabled={loading}>Refresh</button>
          <button className="danger" onClick={() => { sessionStorage.removeItem(TOKEN_KEY); onLogout(); }}>Logout</button>
        </div>
      </header>

      <main className="adv-admin-main">
        <section className="adv-admin-heading">
          <div><span>ADMIN / LIVE MONITORING</span><h1>Security operations dashboard</h1><p>Protected telemetry and recent activity from the CyberShield backend.</p></div>
          <span className="adv-health"><i />SYSTEM HEALTHY</span>
        </section>

        {error && <div className="adv-error adv-dashboard-error">{error}</div>}

        <section className="adv-metrics">
          {metrics.map(([title, value, tone]) => (
            <article className={`adv-metric ${tone}`} key={title}>
              <i /><div><strong>{value}</strong><span>{title}</span></div><small>{tone === "red" ? "Review" : "Live"}</small>
            </article>
          ))}
        </section>

        <section className="adv-admin-grid">
          <article className="adv-feed">
            <div className="adv-panel-head"><h2>Recent security events</h2><span>{recent.length} ITEMS</span></div>
            {loading ? (
              <div className="adv-empty">Loading protected activity…</div>
            ) : recent.length === 0 ? (
              <div className="adv-empty">No recent activity returned by the API.</div>
            ) : (
              <div className="adv-feed-list">
                {recent.slice(0, 12).map((item, i) => {
                  const target = item.url || item.filename || item.file_name || item.email || item.user_identifier || item.username || item.ip_address || item.target || "Security event";
                  const module = item.module || item.type || item.scan_type || item.category || "Scan";
                  const result = item.risk_level || item.prediction || item.status || item.result || "Recorded";
                  const tone = eventTone(result);
                  return (
                    <div className="adv-feed-row" key={`${i}-${target}`}>
                      <i className={tone} />
                      <div><strong>{String(target).slice(0, 72)}</strong><small>{String(module).replaceAll("_", " ")}</small></div>
                      <span className={tone}>{String(result)}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </article>

          <aside className="adv-admin-side">
            <article className="adv-architecture">
              <h2>Security architecture</h2>
              {[
                [LinkIcon, "URL engine", "ML + heuristics", "cyan"],
                [FileIcon, "File scanner", "Static analysis", "indigo"],
                [UserIcon, "Login risk", "Rules + signals", "orange"],
                [DatabaseIcon, "Admin API", "JWT protected", "green"]
              ].map(([Icon, title, sub, tone]) => (
                <div className="adv-arch-row" key={title}><span className={tone}><Icon /></span><div><strong>{title}</strong><small>{sub}</small></div></div>
              ))}
            </article>
            <article className="adv-scope">
              <span>PROJECT SCOPE</span>
              <h2>Decision-support prototype</h2>
              <p>Static analysis and risk scoring assist review. They do not replace antivirus, sandboxing, or human verification.</p>
            </article>
          </aside>
        </section>
      </main>
    </div>
  );
}

function AdminApp() {
  const [token, setToken] = useState(() => sessionStorage.getItem(TOKEN_KEY));
  return token
    ? <Dashboard token={token} onLogout={() => setToken(null)} />
    : <Login onAuthenticated={setToken} />;
}

createRoot(document.getElementById("root")).render(
  <React.StrictMode><AdminApp /></React.StrictMode>
);
