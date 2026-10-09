import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  analyzeEmail,
  analyzeLogin,
  analyzeUrl,
  getPublicStats,
  scanFile,
  scanQr,
  API_BASE_URL
} from "./api";
import {
  LinkIcon,
  FileIcon,
  QrIcon,
  MailIcon,
  UserIcon,
  DatabaseIcon,
  CapIcon,
  GridIcon,
  SearchIcon,
  ArrowIcon,
  ShieldIcon,
  CheckIcon
} from "./icons";

const tools = [
  { id: "url", title: "URL Analyzer", short: "URL", icon: LinkIcon, description: "Check suspicious links before you trust them.", tone: "cyan" },
  { id: "file", title: "File Analyzer", short: "File", icon: FileIcon, description: "Inspect files using static security analysis.", tone: "blue" },
  { id: "qr", title: "QR Analyzer", short: "QR", icon: QrIcon, description: "Decode and review QR destinations safely.", tone: "indigo" },
  { id: "email", title: "Email Analyzer", short: "Email", icon: MailIcon, description: "Review suspicious email content for phishing signals.", tone: "rose" },
  { id: "login", title: "Login Risk", short: "Login", icon: UserIcon, description: "Evaluate unusual sign-in activity and access risk.", tone: "orange" },
  { id: "threats", title: "Threat Intelligence", short: "Intel", icon: DatabaseIcon, description: "Review the signals CyberShield uses during assessment.", tone: "teal" },
  { id: "awareness", title: "Cyber Awareness", short: "Learn", icon: CapIcon, description: "Practical security habits for everyday use.", tone: "violet" }
];

function BrandMark({ className = "" }) {
  return (
    <svg className={className} viewBox="0 0 48 48" fill="none" aria-hidden="true">
      <path d="M24 4.5 39.5 10.8v11.8c0 9.5-5.9 17-15.5 21.4C14.4 39.6 8.5 32.1 8.5 22.6V10.8L24 4.5Z" stroke="currentColor" strokeWidth="2" />
      <path d="M31.8 16.6c-1.9-2.1-4.5-3.2-7.5-3.2-6.2 0-10.7 4.5-10.7 10.6s4.5 10.6 10.7 10.6c3.1 0 5.7-1.1 7.6-3.3" stroke="var(--cs-accent)" strokeWidth="3.2" strokeLinecap="round" />
      <path d="m30.9 20.1 4.5 3.9-4.5 3.9" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function LiquidButton({ children, type = "button", className = "", disabled = false, onClick }) {
  const ref = useRef(null);
  function move(e) {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const x = (e.clientX - r.left) / r.width - 0.5;
    const y = (e.clientY - r.top) / r.height - 0.5;
    el.style.setProperty("--lb-x", `${x * 26}px`);
    el.style.setProperty("--lb-y", `${y * 18}px`);
  }
  function leave() {
    const el = ref.current;
    if (!el) return;
    el.style.setProperty("--lb-x", "0px");
    el.style.setProperty("--lb-y", "0px");
  }
  return (
    <button
      ref={ref}
      type={type}
      className={`csx-liquid-btn ${className}`}
      onPointerMove={move}
      onPointerLeave={leave}
      disabled={disabled}
      onClick={onClick}
    >
      <span className="csx-liquid-blob csx-liquid-a" />
      <span className="csx-liquid-blob csx-liquid-b" />
      <span className="csx-liquid-sheen" />
      <span className="csx-liquid-label">{children}</span>
      <ArrowIcon />
    </button>
  );
}

function usePointerField(ref) {
  useEffect(() => {
    const root = ref.current;
    if (!root) return;
    let raf = 0;
    let tx = window.innerWidth * 0.72;
    let ty = window.innerHeight * 0.28;
    let cx = tx;
    let cy = ty;
    let vx = 0;
    let vy = 0;
    let lastX = tx;
    let lastY = ty;
    let lastT = performance.now();

    const onMove = (e) => {
      const now = performance.now();
      const dt = Math.max(12, now - lastT);
      tx = e.clientX;
      ty = e.clientY;
      vx = (e.clientX - lastX) / dt * 16.67;
      vy = (e.clientY - lastY) / dt * 16.67;
      lastX = e.clientX;
      lastY = e.clientY;
      lastT = now;
    };

    const tick = () => {
      cx += (tx - cx) * 0.115;
      cy += (ty - cy) * 0.115;
      vx *= 0.90;
      vy *= 0.90;
      const speed = Math.min(1, Math.hypot(vx, vy) / 42);
      root.style.setProperty("--mx", `${cx}px`);
      root.style.setProperty("--my", `${cy}px`);
      root.style.setProperty("--mvx", `${Math.max(-36, Math.min(36, vx))}px`);
      root.style.setProperty("--mvy", `${Math.max(-36, Math.min(36, vy))}px`);
      root.style.setProperty("--mspeed", speed.toFixed(3));
      raf = requestAnimationFrame(tick);
    };

    window.addEventListener("pointermove", onMove, { passive: true });
    raf = requestAnimationFrame(tick);
    return () => {
      window.removeEventListener("pointermove", onMove);
      cancelAnimationFrame(raf);
    };
  }, [ref]);
}

function normalizeScore(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  return n <= 1 ? n * 100 : n;
}

function assessment(result) {
  if (!result) return null;
  const prediction =
    result.prediction ??
    result.label ??
    result.verdict ??
    result.classification ??
    result.status ??
    result.result ??
    "Assessment complete";
  const risk =
    result.risk_level ??
    result.risk ??
    result.severity ??
    result.threat_level ??
    prediction;
  const score = normalizeScore(
    result.risk_score ??
    result.score ??
    result.probability ??
    result.malicious_probability ??
    result.confidence
  );
  const confidence = normalizeScore(result.confidence);
  const reasonSource =
    result.reasons ??
    result.reason ??
    result.indicators ??
    result.findings ??
    result.explanation ??
    [];
  const reasons = Array.isArray(reasonSource)
    ? reasonSource
    : typeof reasonSource === "string"
      ? [reasonSource]
      : reasonSource && typeof reasonSource === "object"
        ? Object.entries(reasonSource).map(([k, v]) => `${k.replaceAll("_", " ")}: ${String(v)}`)
        : [];
  return { prediction: String(prediction), risk: String(risk), score, confidence, reasons };
}

function riskTone(value, score) {
  const s = String(value || "").toLowerCase();
  if (/malicious|high|danger|phish|critical|unsafe|threat/.test(s) || (score ?? 0) >= 70) return "high";
  if (/medium|moderate|review|suspicious|warn/.test(s) || (score ?? 0) >= 35) return "medium";
  return "safe";
}

function ResultPanel({ result, loading, error }) {
  if (loading) {
    return (
      <aside className="csx-result csx-result-loading">
        <div className="csx-loader-orbit"><span /></div>
        <strong>Analyzing security signals</strong>
        <p>CyberShield is combining available indicators into a decision-support result.</p>
      </aside>
    );
  }
  if (error) {
    return (
      <aside className="csx-result">
        <span className="csx-kicker">ANALYSIS ERROR</span>
        <h3>Could not complete this scan</h3>
        <p className="csx-error">{error}</p>
      </aside>
    );
  }
  const a = assessment(result);
  if (!a) {
    return (
      <aside className="csx-result csx-result-empty">
        <span className="csx-kicker">LATEST ASSESSMENT</span>
        <div className="csx-empty-orbit"><ShieldIcon /></div>
        <h3>Ready for analysis</h3>
        <p>Your result will appear here with risk score, evidence and recommended next action.</p>
      </aside>
    );
  }
  const tone = riskTone(a.risk, a.score);
  const score = Math.max(0, Math.min(100, a.score ?? (tone === "high" ? 84 : tone === "medium" ? 52 : 18)));
  return (
    <aside className={`csx-result tone-${tone}`}>
      <span className="csx-kicker">LATEST ASSESSMENT</span>
      <h3>{a.prediction}</h3>
      <span className={`csx-risk-pill ${tone}`}>{a.risk}</span>
      <div className="csx-score-wrap">
        <div className="csx-score-ring" style={{ "--score": `${score * 3.6}deg` }}>
          <div><strong>{Math.round(score)}</strong><span>%</span><small>RISK SCORE</small></div>
        </div>
      </div>
      <div className="csx-result-divider" />
      <h4>Why this result</h4>
      <div className="csx-reasons">
        {(a.reasons.length ? a.reasons : [
          tone === "safe" ? "No strong malicious indicator was detected." : "The submitted item contains signals that require additional review.",
          "CyberShield combines multiple indicators rather than relying on a single check."
        ]).slice(0, 5).map((item, i) => (
          <div key={i}><span className={`csx-dot ${tone}`} /><p>{item}</p></div>
        ))}
      </div>
      {a.confidence != null && (
        <div className="csx-confidence"><span>Confidence</span><strong>{Math.round(a.confidence)}%</strong></div>
      )}
      <div className="csx-result-divider" />
      <h4>Recommended action</h4>
      <p className="csx-recommend">
        {tone === "high"
          ? "Do not trust or open this item until it is verified through a trusted security process."
          : tone === "medium"
            ? "Treat this item with caution and verify the source before proceeding."
            : "No major threat signal was detected, but continue to verify important actions independently."}
      </p>
    </aside>
  );
}

function FileDrop({ file, setFile, accept, icon: Icon = FileIcon, title, subtitle }) {
  return (
    <label className="csx-file-drop">
      <input type="file" accept={accept} onChange={(e) => setFile(e.target.files?.[0] || null)} />
      <span className="csx-upload-bubble"><Icon /></span>
      <strong>{file ? file.name : title}</strong>
      <small>{subtitle}</small>
    </label>
  );
}

function ToolForm({ toolId, onRun, loading }) {
  const [url, setUrl] = useState("");
  const [file, setFile] = useState(null);
  const [qr, setQr] = useState(null);
  const [email, setEmail] = useState({ sender_email: "", reply_to_email: "", subject: "", body: "" });
  const [login, setLogin] = useState({
    user_identifier: "",
    ip_address: "",
    failed_attempts: 0,
    new_device: false,
    unusual_location: false,
    login_hour: new Date().getHours()
  });

  if (toolId === "url") {
    return (
      <form className="csx-tool-form" onSubmit={(e) => { e.preventDefault(); if (url.trim()) onRun(() => analyzeUrl(url.trim())); }}>
        <div className="csx-form-head"><span>ANALYSIS INPUT</span><strong>Check a suspicious URL</strong></div>
        <label>Suspicious URL</label>
        <div className="csx-input-row"><LinkIcon /><input value={url} onChange={(e) => setUrl(e.target.value)} type="url" required placeholder="https://example.com" /></div>
        <div className="csx-form-actions"><LiquidButton type="submit" disabled={loading}>{loading ? "Analyzing..." : "Analyze URL"}</LiquidButton><span>ML + security heuristics</span></div>
      </form>
    );
  }

  if (toolId === "file") {
    return (
      <form className="csx-tool-form" onSubmit={(e) => { e.preventDefault(); if (file) onRun(() => scanFile(file)); }}>
        <div className="csx-form-head"><span>STATIC INSPECTION</span><strong>Inspect a suspicious file</strong></div>
        <FileDrop file={file} setFile={setFile} icon={FileIcon} title="Drop a file here or browse" subtitle="Static analysis only — CyberShield does not execute the file." />
        <div className="csx-form-actions"><LiquidButton type="submit" disabled={loading || !file}>{loading ? "Scanning..." : "Scan file"}</LiquidButton><span>Local static analysis</span></div>
      </form>
    );
  }

  if (toolId === "qr") {
    return (
      <form className="csx-tool-form" onSubmit={(e) => { e.preventDefault(); if (qr) onRun(() => scanQr(qr)); }}>
        <div className="csx-form-head"><span>ENCODED DESTINATION</span><strong>Inspect a QR code</strong></div>
        <FileDrop file={qr} setFile={setQr} accept="image/*" icon={QrIcon} title="Drop a QR image here" subtitle="CyberShield decodes the destination and analyzes the resolved URL." />
        <div className="csx-form-actions"><LiquidButton type="submit" disabled={loading || !qr}>{loading ? "Decoding..." : "Analyze QR"}</LiquidButton><span>Image → URL → assessment</span></div>
      </form>
    );
  }

  if (toolId === "email") {
    return (
      <form className="csx-tool-form" onSubmit={(e) => { e.preventDefault(); onRun(() => analyzeEmail({ ...email, reply_to_email: email.reply_to_email.trim() || null })); }}>
        <div className="csx-form-head"><span>PHISHING REVIEW</span><strong>Inspect an email message</strong></div>
        <div className="csx-form-grid">
          <label>Sender<input type="email" value={email.sender_email} onChange={(e) => setEmail(v => ({ ...v, sender_email: e.target.value }))} placeholder="security@example.com" /></label>
          <label>Reply-To<input type="email" value={email.reply_to_email} onChange={(e) => setEmail(v => ({ ...v, reply_to_email: e.target.value }))} placeholder="optional@example.com" /></label>
        </div>
        <label>Subject<input value={email.subject} onChange={(e) => setEmail(v => ({ ...v, subject: e.target.value }))} placeholder="Email subject" /></label>
        <label>Message<textarea rows="7" value={email.body} onChange={(e) => setEmail(v => ({ ...v, body: e.target.value }))} placeholder="Paste the suspicious message here..." /></label>
        <div className="csx-form-actions"><LiquidButton type="submit" disabled={loading}>{loading ? "Analyzing..." : "Analyze email"}</LiquidButton><span>Sender + content signals</span></div>
      </form>
    );
  }

  if (toolId === "login") {
    return (
      <form className="csx-tool-form" onSubmit={(e) => { e.preventDefault(); onRun(() => analyzeLogin(login)); }}>
        <div className="csx-form-head"><span>ACCESS RISK</span><strong>Evaluate login activity</strong></div>
        <div className="csx-form-grid">
          <label>User identifier<input required value={login.user_identifier} onChange={(e) => setLogin(v => ({ ...v, user_identifier: e.target.value }))} placeholder="user001" /></label>
          <label>IP address<input required value={login.ip_address} onChange={(e) => setLogin(v => ({ ...v, ip_address: e.target.value }))} placeholder="192.168.1.20" /></label>
          <label>Failed attempts<input type="number" min="0" value={login.failed_attempts} onChange={(e) => setLogin(v => ({ ...v, failed_attempts: Number(e.target.value) }))} /></label>
          <label>Login hour<input type="number" min="0" max="23" value={login.login_hour} onChange={(e) => setLogin(v => ({ ...v, login_hour: Number(e.target.value) }))} /></label>
        </div>
        <div className="csx-switches">
          <label><input type="checkbox" checked={login.new_device} onChange={(e) => setLogin(v => ({ ...v, new_device: e.target.checked }))} /><span>New or unknown device</span></label>
          <label><input type="checkbox" checked={login.unusual_location} onChange={(e) => setLogin(v => ({ ...v, unusual_location: e.target.checked }))} /><span>Unusual location</span></label>
        </div>
        <div className="csx-form-actions"><LiquidButton type="submit" disabled={loading}>{loading ? "Checking..." : "Analyze login"}</LiquidButton><span>Transparent rule scoring</span></div>
      </form>
    );
  }

  return null;
}

function IntelligencePanel() {
  const items = [
    ["URL engine", "Lexical features, URL structure, redirects and security heuristics.", "cyan"],
    ["File scanner", "Static metadata, hashes and suspicious indicators. No execution.", "blue"],
    ["Email signals", "Sender, reply-to, subject and message patterns associated with phishing.", "rose"],
    ["Login risk", "Failed attempts, device novelty, location and time-based indicators.", "orange"]
  ];
  return (
    <div className="csx-info-workspace">
      <div className="csx-form-head"><span>THREAT INTELLIGENCE</span><strong>What CyberShield evaluates</strong></div>
      <p>CyberShield combines multiple security signals to support a decision. It does not treat a single indicator as proof of compromise.</p>
      <div className="csx-intel-grid">
        {items.map(([t, d, tone]) => <article key={t} className={`tone-${tone}`}><span /><h4>{t}</h4><p>{d}</p></article>)}
      </div>
      <div className="csx-boundary-note"><ShieldIcon /><div><strong>Decision-support boundary</strong><p>Static analysis and risk scoring assist review. They do not replace antivirus, sandboxing, provider reputation systems, or human verification.</p></div></div>
    </div>
  );
}

function AwarenessPanel() {
  const tips = [
    ["Phishing", "Verify the sender and destination before entering passwords or payment details."],
    ["QR codes", "Treat unknown QR codes like unknown links. Preview the destination first."],
    ["Files", "Do not open unexpected attachments, especially executables or macro-enabled documents."],
    ["Passwords", "Use unique passwords and multi-factor authentication for important accounts."],
    ["Login alerts", "Unexpected device or location alerts should be reviewed immediately."],
    ["Urgency", "Pressure, threats and time-limited rewards are common social-engineering tactics."]
  ];
  return (
    <div className="csx-info-workspace">
      <div className="csx-form-head"><span>CYBER AWARENESS</span><strong>Practical habits that reduce risk</strong></div>
      <div className="csx-awareness-grid">
        {tips.map(([t, d], i) => <article key={t}><span>{String(i + 1).padStart(2, "0")}</span><h4>{t}</h4><p>{d}</p></article>)}
      </div>
    </div>
  );
}

function Workspace({ tool, onHome }) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => { setResult(null); setError(""); }, [tool.id]);

  async function run(action) {
    setLoading(true);
    setError("");
    setResult(null);
    try {
      setResult(await action());
    } catch (e) {
      setError(e?.message || "Something went wrong.");
    } finally {
      setLoading(false);
    }
  }

  const Icon = tool.icon;
  if (tool.id === "threats" || tool.id === "awareness") {
    return (
      <section className="csx-workspace-view">
        <div className="csx-workspace-title">
          <button className="csx-back" onClick={onHome}>← Command</button>
          <div><span>{tool.id === "threats" ? "INTELLIGENCE" : "LEARNING"}</span><h1>{tool.title}</h1><p>{tool.description}</p></div>
        </div>
        <div className="csx-wide-info">{tool.id === "threats" ? <IntelligencePanel /> : <AwarenessPanel />}</div>
      </section>
    );
  }

  return (
    <section className="csx-workspace-view">
      <div className="csx-workspace-title">
        <button className="csx-back" onClick={onHome}>← Command</button>
        <div><span>{tool.short.toUpperCase()} / ANALYZER</span><h1>{tool.title}</h1><p>{tool.description}</p></div>
      </div>
      <div className="csx-workspace-grid">
        <div className="csx-analyzer-panel">
          <div className={`csx-tool-badge tone-${tool.tone}`}><Icon /></div>
          <ToolForm toolId={tool.id} onRun={run} loading={loading} />
        </div>
        <ResultPanel result={result} loading={loading} error={error} />
      </div>
    </section>
  );
}

function MetricCard({ value, label, meta, tone }) {
  return (
    <article className={`csx-metric tone-${tone}`}>
      <span className="csx-metric-dot" />
      <div><strong>{value}</strong><span>{label}</span></div>
      <small>{meta}</small>
    </article>
  );
}

function normalizeStats(data) {
  const overall = data?.overall || data || {};
  const url = data?.url_scanner || {};
  const file = data?.file_scanner || {};
  return {
    total: overall.total_scans ?? overall.total ?? data?.total_scans ?? "—",
    urls: url.total ?? data?.url_scans ?? data?.urls ?? "—",
    files: file.total ?? data?.file_scans ?? data?.files ?? "—",
    threats: overall.confirmed_threats ?? data?.threats ?? data?.high_risk ?? "—"
  };
}

function Home({ stats, apiOnline, onOpenTool }) {
  const s = normalizeStats(stats);
  const [quickUrl, setQuickUrl] = useState("");
  const [quickLoading, setQuickLoading] = useState(false);
  const [quickResult, setQuickResult] = useState(null);
  const [quickError, setQuickError] = useState("");

  async function quick(e) {
    e.preventDefault();
    if (!quickUrl.trim()) return;
    setQuickLoading(true);
    setQuickError("");
    setQuickResult(null);
    try { setQuickResult(await analyzeUrl(quickUrl.trim())); }
    catch (err) { setQuickError(err?.message || "Quick analysis failed."); }
    finally { setQuickLoading(false); }
  }
  const quickAssessment = assessment(quickResult);

  return (
    <section className="csx-home-view">
      <div className="csx-home-intro">
        <span>CYBERSHIELD / COMMAND</span>
        <h1>Security Command Center</h1>
        <p>Analyze suspicious activity, review risk signals, and act from one focused workspace.</p>
      </div>

      <div className="csx-home-top">
        <div className="csx-metrics-row">
          <MetricCard value={s.urls} label="URL scans" meta="Threat analysis" tone="cyan" />
          <MetricCard value={s.files} label="File scans" meta="Static inspection" tone="blue" />
          <MetricCard value={s.threats} label="High-risk" meta="Needs review" tone="rose" />
        </div>
        <form className="csx-quick-card" onSubmit={quick}>
          <span className="csx-kicker">QUICK ANALYSIS</span>
          <h2>Check a URL before you trust it.</h2>
          <div className="csx-quick-input"><SearchIcon /><input type="url" required value={quickUrl} onChange={(e) => setQuickUrl(e.target.value)} placeholder="https://example.com" /></div>
          <div className="csx-quick-actions"><span>ML + HEURISTICS</span><LiquidButton type="submit" disabled={quickLoading}>{quickLoading ? "Analyzing..." : "Run scan"}</LiquidButton></div>
          {(quickAssessment || quickError) && (
            <div className={`csx-quick-result ${quickError ? "error" : riskTone(quickAssessment?.risk, quickAssessment?.score)}`}>
              <strong>{quickError || quickAssessment?.prediction}</strong>
              {!quickError && <span>{quickAssessment?.score != null ? `${Math.round(quickAssessment.score)}% risk` : quickAssessment?.risk}</span>}
            </div>
          )}
        </form>
      </div>

      <div className="csx-home-bottom">
        <article className="csx-activity-panel">
          <div className="csx-panel-head"><h3>Threat activity</h3><span>LOCAL SESSION</span></div>
          <div className="csx-bars">{[24,38,34,56,42,70,64,86,54,72,68,44,62,90,74,96,70,56,72,48,62,54,40,52].map((v,i)=><i key={i} style={{height:`${v}%`}} />)}</div>
          <p>Visual activity is a session indicator, not proof of compromise.</p>
          <div className="csx-tool-shortcuts">
            {tools.slice(0,5).map((tool) => {
              const Icon = tool.icon;
              return <button key={tool.id} onClick={() => onOpenTool(tool.id)}><span className={`tone-${tool.tone}`}><Icon /></span><div><strong>{tool.title}</strong><small>{tool.description}</small></div><ArrowIcon /></button>;
            })}
          </div>
        </article>

        <aside className="csx-status-panel">
          <div className="csx-panel-head"><h3>Protection status</h3><span>{apiOnline ? "ONLINE" : "CHECK API"}</span></div>
          <div className="csx-system-score"><div><strong>{apiOnline ? "92" : "—"}</strong><small>SYSTEM SCORE</small></div></div>
          <span className={`csx-engine-pill ${apiOnline ? "online" : ""}`}>{apiOnline ? "ENGINE ONLINE" : "ENGINE UNREACHABLE"}</span>
          <div className="csx-status-list">
            <div><span>API endpoint</span><strong>{apiOnline ? "Ready" : "Offline"}</strong></div>
            <div><span>Local frontend</span><strong>Ready</strong></div>
            <div><span>Data layer</span><strong>Configured</strong></div>
          </div>
          <button className="csx-admin-link" onClick={() => { window.location.href = "/admin.html"; }}>Open admin console <ArrowIcon /></button>
        </aside>
      </div>
    </section>
  );
}

function Header({ apiOnline }) {
  return (
    <header className="csx-topbar">
      <a className="csx-brand" href="/" onClick={(e) => { e.preventDefault(); window.location.href = "/"; }}>
        <BrandMark />
        <span><strong>CyberShield</strong><small>SECURITY CONSOLE</small></span>
      </a>
      <div className={`csx-engine ${apiOnline ? "online" : ""}`}><i />{apiOnline ? "LOCAL ENGINE" : "ENGINE CHECK"}</div>
      <button className="csx-user" onClick={() => { window.location.href = "/admin.html"; }}><span>ADMIN</span><i /></button>
    </header>
  );
}

function Rail({ active, onSelect }) {
  return (
    <nav className="csx-rail" aria-label="CyberShield tools">
      <button className={!active ? "active" : ""} onClick={() => onSelect(null)} title="Command Center"><GridIcon /></button>
      {tools.map((tool) => {
        const Icon = tool.icon;
        return <button key={tool.id} className={active === tool.id ? "active" : ""} onClick={() => onSelect(tool.id)} title={tool.title}><Icon /></button>;
      })}
    </nav>
  );
}

export default function App() {
  const rootRef = useRef(null);
  usePointerField(rootRef);
  const [active, setActive] = useState(null);
  const [stats, setStats] = useState(null);
  const [apiOnline, setApiOnline] = useState(false);

  useEffect(() => {
    let mounted = true;
    getPublicStats()
      .then((data) => { if (mounted) { setStats(data); setApiOnline(true); } })
      .catch(() => { if (mounted) setApiOnline(false); });
    return () => { mounted = false; };
  }, []);

  const tool = useMemo(() => tools.find(t => t.id === active), [active]);

  return (
    <div ref={rootRef} className="csx-app">
      <div className="csx-pointer-field" aria-hidden="true">
        <span className="fluid fluid-a" />
        <span className="fluid fluid-b" />
        <span className="wake wake-1" />
        <span className="wake wake-2" />
        <span className="wake wake-3" />
      </div>
      <Header apiOnline={apiOnline} />
      <Rail active={active} onSelect={setActive} />
      <main className="csx-main">
        {tool ? <Workspace tool={tool} onHome={() => setActive(null)} /> : <Home stats={stats} apiOnline={apiOnline} onOpenTool={setActive} />}
      </main>
      <footer className="csx-runtime">API {API_BASE_URL}</footer>
    </div>
  );
}
