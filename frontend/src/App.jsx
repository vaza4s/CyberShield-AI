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
  CloseIcon
} from "./icons";

const tools = [
  { id: "url", title: "URL Analyzer", short: "URL", icon: LinkIcon, description: "Detect phishing and malicious links.", tone: "cyan" },
  { id: "file", title: "File Analyzer", short: "File", icon: FileIcon, description: "Scan files for suspicious indicators.", tone: "violet" },
  { id: "qr", title: "QR Analyzer", short: "QR", icon: QrIcon, description: "Inspect QR codes before opening them.", tone: "purple" },
  { id: "email", title: "Email Analyzer", short: "Email", icon: MailIcon, description: "Check email text for phishing and scams.", tone: "rose" },
  { id: "login", title: "Login Risk", short: "Login", icon: UserIcon, description: "Analyze unusual and suspicious login activity.", tone: "orange" },
  { id: "threats", title: "Threat Intelligence", short: "Intel", icon: DatabaseIcon, description: "Review threat activity and attack patterns.", tone: "teal" },
  { id: "awareness", title: "Cyber Awareness", short: "Learn", icon: CapIcon, description: "Learn safer habits and common threat tactics.", tone: "indigo" }
];

const BRANCH_ASSET = "/assets/cybershield-brand.svg";
const HERO_ASSET = "/assets/cybershield-hero.svg";

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function useMouseFlow(rootRef) {
  useEffect(() => {
    const root = rootRef.current;
    if (!root) return;

    let raf = 0;
    let tx = window.innerWidth * 0.46;
    let ty = window.innerHeight * 0.35;
    let cx = tx;
    let cy = ty;
    let vx = 0;
    let vy = 0;
    let px = tx;
    let py = ty;
    let last = performance.now();

    const pointerMove = (event) => {
      const now = performance.now();
      const dt = Math.max(8, now - last);
      tx = event.clientX;
      ty = event.clientY;
      vx = ((event.clientX - px) / dt) * 16.67;
      vy = ((event.clientY - py) / dt) * 16.67;
      px = event.clientX;
      py = event.clientY;
      last = now;
    };

    const animate = () => {
      cx += (tx - cx) * 0.14;
      cy += (ty - cy) * 0.14;
      vx *= 0.91;
      vy *= 0.91;

      const speed = clamp(Math.hypot(vx, vy) / 42, 0, 1);
      const angle = Math.atan2(vy, vx || 0.001) * (180 / Math.PI);

      root.style.setProperty("--mouse-x", `${cx}px`);
      root.style.setProperty("--mouse-y", `${cy}px`);
      root.style.setProperty("--flow-x", `${clamp(vx, -42, 42)}px`);
      root.style.setProperty("--flow-y", `${clamp(vy, -42, 42)}px`);
      root.style.setProperty("--flow-speed", speed.toFixed(3));
      root.style.setProperty("--flow-angle", `${angle.toFixed(2)}deg`);
      root.style.setProperty("--flow-stretch", (1 + speed * 0.72).toFixed(3));
      root.style.setProperty("--flow-squash", (1 - speed * 0.16).toFixed(3));

      raf = requestAnimationFrame(animate);
    };

    window.addEventListener("pointermove", pointerMove, { passive: true });
    raf = requestAnimationFrame(animate);

    return () => {
      window.removeEventListener("pointermove", pointerMove);
      cancelAnimationFrame(raf);
    };
  }, [rootRef]);
}

function BackgroundMotion() {
  return (
    <div className="cs-motion" aria-hidden="true">
      <svg className="cs-flow-lines" viewBox="0 0 1536 960" preserveAspectRatio="none">
        <defs>
          <linearGradient id="flowA" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stopColor="#139cff" stopOpacity="0" />
            <stop offset=".42" stopColor="#19b8ff" stopOpacity=".32" />
            <stop offset=".74" stopColor="#6a4cff" stopOpacity=".28" />
            <stop offset="1" stopColor="#7840ff" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="flowB" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0" stopColor="#4adcf8" stopOpacity="0" />
            <stop offset=".5" stopColor="#4adcf8" stopOpacity=".18" />
            <stop offset="1" stopColor="#5c4dff" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path className="flow-line line-a" d="M-120 590 C230 455, 410 720, 760 585 S1280 510, 1660 640" stroke="url(#flowA)" />
        <path className="flow-line line-b" d="M-100 640 C240 520, 520 770, 820 630 S1230 540, 1640 705" stroke="url(#flowB)" />
        <path className="flow-line line-c" d="M-80 755 C300 615, 500 820, 875 710 S1290 655, 1620 785" stroke="url(#flowA)" />
      </svg>
      <div className="cs-cursor-glow" />
      <div className="cs-wake wake-one" />
      <div className="cs-wake wake-two" />
      <div className="cs-wake wake-three" />
      <div className="cs-ripple ripple-lg" />
      <div className="cs-ripple ripple-md" />
      <div className="cs-ripple ripple-sm" />
      <div className="cs-ambient cs-ambient-blue" />
      <div className="cs-ambient cs-ambient-purple" />
    </div>
  );
}

function Brand({ compact = false }) {
  return (
    <div className={`cs-brand ${compact ? "compact" : ""}`}>
      <img src={BRANCH_ASSET} alt="" />
      <div>
        <div className="cs-brand-line"><strong>CyberShield</strong><b>AI</b></div>
        <small>Detect&nbsp;&nbsp; • &nbsp;&nbsp;Prevent&nbsp;&nbsp; • &nbsp;&nbsp;Stay Safe</small>
      </div>
    </div>
  );
}

function pick(obj, paths, fallback = "—") {
  for (const path of paths) {
    const value = path.split(".").reduce((acc, key) => acc?.[key], obj);
    if (value !== undefined && value !== null && value !== "") return value;
  }
  return fallback;
}

function normalizeStats(data) {
  return {
    urls: pick(data, ["url_scanner.total", "url_scans", "urls_scanned", "urls"]),
    files: pick(data, ["file_scanner.total", "file_scans", "files_scanned", "files"]),
    logins: pick(data, ["login_risk.total", "login_scans", "login_analyzed", "logins"]),
    threats: pick(data, ["overall.confirmed_threats", "threats_detected", "high_risk", "threats"])
  };
}

function normalizeScore(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  return n <= 1 ? n * 100 : n;
}

function readAssessment(result) {
  if (!result) return null;
  const label =
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
    label;

  const score = normalizeScore(
    result.risk_score ??
    result.score ??
    result.probability ??
    result.malicious_probability ??
    result.confidence
  );

  const rawReasons =
    result.reasons ??
    result.reason ??
    result.indicators ??
    result.findings ??
    result.explanation ??
    [];

  const reasons = Array.isArray(rawReasons)
    ? rawReasons
    : typeof rawReasons === "string"
      ? [rawReasons]
      : rawReasons && typeof rawReasons === "object"
        ? Object.entries(rawReasons).map(([key, value]) => `${key.replaceAll("_", " ")}: ${String(value)}`)
        : [];

  return { label: String(label), risk: String(risk), score, reasons };
}

function toneFrom(value, score) {
  const text = String(value || "").toLowerCase();
  if (/malicious|high|danger|critical|phish|unsafe|threat/.test(text) || (score ?? 0) >= 70) return "high";
  if (/medium|moderate|review|warning|suspicious/.test(text) || (score ?? 0) >= 35) return "medium";
  return "safe";
}

function Header({ online, onSelect }) {
  const nav = [
    ["home", GridIcon, "Home"],
    ["url", LinkIcon, "URL Scanner"],
    ["file", FileIcon, "File Scanner"],
    ["login", UserIcon, "Login Risk"],
    ["history", SearchIcon, "History"]
  ];

  return (
    <header className="cs-header">
      <Brand />
      <nav className="cs-nav">
        {nav.map(([id, Icon, label]) => (
          <button key={id} className={id === "home" ? "active" : ""} onClick={() => onSelect(id)}>
            <Icon />
            <span>{label}</span>
          </button>
        ))}
      </nav>
      <div className={`cs-engine ${online ? "online" : ""}`}><i />{online ? "Engine Online" : "Engine Check"}</div>
      <button className="cs-profile" onClick={() => { window.location.href = "/admin.html"; }} aria-label="Open admin dashboard">
        <UserIcon />
      </button>
    </header>
  );
}

function Hero({ onOpen }) {
  return (
    <section className="cs-hero">
      <div className="cs-hero-copy">
        <div className="cs-ai-pill"><ShieldIcon /><span>AI POWERED CYBER SECURITY</span></div>
        <h1>Stay One Step <span>Ahead</span></h1>
        <p>Scan suspicious URLs, analyze files, and detect risky login activities using advanced AI. Fast. Accurate. Secure.</p>
        <div className="cs-hero-actions">
          <button className="cs-primary" onClick={() => onOpen("url")}><span className="play-dot">▶</span>Start Scanning</button>
          <button className="cs-secondary" onClick={() => onOpen("awareness")}><GridIcon />Learn More</button>
        </div>
      </div>

      <div className="cs-hero-visual">
        <img className="cs-hero-core" src={HERO_ASSET} alt="CyberShield security core" />
        <button className="cs-feature feature-url" onClick={() => onOpen("url")}><span><LinkIcon /></span><small>URL Analysis</small></button>
        <button className="cs-feature feature-login" onClick={() => onOpen("login")}><span><UserIcon /></span><small>Login Risk</small></button>
        <button className="cs-feature feature-file" onClick={() => onOpen("file")}><span><FileIcon /></span><small>File Scanning</small></button>
        <button className="cs-feature feature-protect" onClick={() => onOpen("threats")}><span><DatabaseIcon /></span><small>Real-time Protection</small></button>
      </div>
    </section>
  );
}

function ToolCards({ onOpen }) {
  return (
    <section className="cs-tools">
      {tools.map((tool) => {
        const Icon = tool.icon;
        return (
          <button key={tool.id} className={`cs-tool-card tone-${tool.tone}`} onClick={() => onOpen(tool.id)}>
            <span className="cs-card-glow" />
            <span className="cs-card-icon"><Icon /></span>
            <span className="cs-card-copy"><strong>{tool.title}</strong><small>{tool.description}</small></span>
            <span className="cs-card-open"><ArrowIcon /></span>
          </button>
        );
      })}
    </section>
  );
}

function SessionDistribution({ history }) {
  const total = history.length;
  const counts = history.reduce((acc, item) => {
    acc[item.tone] = (acc[item.tone] || 0) + 1;
    return acc;
  }, { safe: 0, medium: 0, high: 0 });

  const low = total ? Math.round((counts.safe / total) * 100) : 0;
  const medium = total ? Math.round((counts.medium / total) * 100) : 0;
  const high = total ? Math.max(0, 100 - low - medium) : 0;
  const ring = total
    ? `conic-gradient(#1ba7ff 0 ${low}%, #ff9b55 ${low}% ${low + medium}%, #ff5c8a ${low + medium}% 100%)`
    : "conic-gradient(#163252 0 100%)";

  return (
    <article className="cs-bottom-panel cs-threat-panel">
      <div className="cs-bottom-head"><h3>Threat Distribution</h3></div>
      <div className="cs-threat-body">
        <div className="cs-risk-ring" style={{ background: ring }}><div><strong>{total ? `${low}%` : "—"}</strong></div></div>
        <div className="cs-legend">
          <div><i className="low" /><span>Low Risk</span><b>{total ? `${low}%` : "—"}</b></div>
          <div><i className="medium" /><span>Medium</span><b>{total ? `${medium}%` : "—"}</b></div>
          <div><i className="high" /><span>High Risk</span><b>{total ? `${high}%` : "—"}</b></div>
        </div>
      </div>
    </article>
  );
}

function BottomDashboard({ stats, history }) {
  const s = normalizeStats(stats);
  const statsCards = [
    [LinkIcon, s.urls, "URLs Scanned", "cyan"],
    [FileIcon, s.files, "Files Scanned", "rose"],
    [UserIcon, s.logins, "Login Analyzed", "violet"],
    [ShieldIcon, s.threats, "Threats Detected", "green"]
  ];

  return (
    <section className="cs-bottom-grid" id="history-section">
      <article className="cs-bottom-panel cs-overview">
        <div className="cs-bottom-head"><h3>System Overview</h3><span>Last 7 Days</span></div>
        <div className="cs-stat-grid">
          {statsCards.map(([Icon, value, label, tone]) => (
            <div key={label} className={`cs-stat tone-${tone}`}><span><Icon /></span><strong>{value}</strong><small>{label}</small></div>
          ))}
        </div>
      </article>

      <SessionDistribution history={history} />

      <article className="cs-bottom-panel cs-recent">
        <div className="cs-bottom-head"><h3>Recent Scans</h3><span>View All →</span></div>
        <div className="cs-recent-list">
          {history.length === 0 ? (
            <div className="cs-empty-history">Run a scan to populate this session.</div>
          ) : history.slice(0, 3).map((item, index) => {
            const Icon = item.icon;
            return (
              <div className="cs-recent-row" key={item.id}>
                <span className="recent-icon"><Icon /></span>
                <div><strong>{item.target}</strong><small>{item.label} • {index === 0 ? "Just now" : `${index * 2} min ago`}</small></div>
                <b className={item.tone}>{item.status}</b>
              </div>
            );
          })}
        </div>
      </article>
    </section>
  );
}

function FileDrop({ file, setFile, accept = undefined, icon: Icon = FileIcon, title = "Select a file to inspect", caption = "Static analysis only — the file is not executed." }) {
  return (
    <label className="cs-file-drop">
      <input type="file" accept={accept} onChange={(event) => setFile(event.target.files?.[0] || null)} />
      <span><Icon /></span>
      <strong>{file ? file.name : title}</strong>
      <small>{caption}</small>
    </label>
  );
}

function CompactResult({ result, error, loading }) {
  if (loading) {
    return (
      <section className="cs-result-card loading">
        <div className="cs-result-loader"><i /></div>
        <div><strong>Analyzing security signals…</strong><span>Combining model output and security indicators.</span></div>
      </section>
    );
  }

  if (error) {
    return (
      <section className="cs-result-card error">
        <span className="cs-result-kicker">ANALYSIS ERROR</span>
        <h3>Could not complete this scan</h3>
        <p>{error}</p>
      </section>
    );
  }

  const a = readAssessment(result);
  if (!a) return null;

  const tone = toneFrom(a.risk, a.score);
  const hasScore = a.score != null && Number.isFinite(Number(a.score));
  const score = hasScore ? clamp(Number(a.score), 0, 100) : 0;
  const scoreLabel = hasScore ? String(Math.round(score)) : "—";
  const circumference = 2 * Math.PI * 54;
  const dash = hasScore ? circumference * (score / 100) : 0;
  const remaining = circumference - dash;

  const recommendation =
    tone === "high"
      ? "Do not trust, open, or continue with this item until it is independently verified."
      : tone === "medium"
        ? "Treat this item with caution. Verify the source and destination before continuing."
        : "No major malicious signal was detected, but important actions should still be independently verified.";

  return (
    <section className={`cs-result-card ${tone}`}>
      <div className="cs-result-top">
        <div>
          <span className="cs-result-kicker">RISK ASSESSMENT</span>
          <h3>{a.label}</h3>
          <span className={`cs-result-status ${tone}`}>{a.risk}</span>
        </div>

        <div className="cs-risk-donut" aria-label={hasScore ? `Risk score ${Math.round(score)} percent` : "Risk score unavailable"}>
          <svg viewBox="0 0 128 128" aria-hidden="true">
            <circle className="donut-track" cx="64" cy="64" r="54" />
            <circle
              className="donut-value"
              cx="64"
              cy="64"
              r="54"
              pathLength={circumference}
              strokeDasharray={`${dash} ${remaining}`}
            />
          </svg>
          <div><strong>{scoreLabel}</strong><span>{hasScore ? "%" : ""}</span><small>RISK SCORE</small></div>
        </div>
      </div>

      <div className="cs-result-separator" />

      <div className="cs-result-section">
        <h4>Why this was flagged</h4>
        <div className="cs-result-reasons">
          {(a.reasons.length
            ? a.reasons
            : [tone === "safe"
                ? "No strong malicious indicator was returned by the current assessment."
                : "The current assessment contains indicators that require further review."]
          ).slice(0, 4).map((reason, index) => (
            <div key={index}><i className={tone} /><span>{reason}</span></div>
          ))}
        </div>
      </div>

      <div className="cs-result-separator" />

      <div className="cs-result-section recommendation">
        <h4>Recommended action</h4>
        <p>{recommendation}</p>
      </div>
    </section>
  );
}

function ToolModal({ tool, onClose, onRecord }) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
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

  useEffect(() => {
    const key = (event) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [onClose]);

  if (!tool) return null;
  const Icon = tool.icon;

  async function run(action, target) {
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const data = await action();
      setResult(data);
      const a = readAssessment(data);
      const tone = toneFrom(a?.risk, a?.score);
      const status = tone === "high" ? "High Risk" : tone === "medium" ? "Review" : "Safe";
      onRecord({
        id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
        target: String(target || tool.title).slice(0, 44),
        label: tool.title,
        status,
        tone,
        icon: Icon
      });
    } catch (err) {
      setError(err?.message || "Something went wrong.");
    } finally {
      setLoading(false);
    }
  }

  let content = null;

  if (tool.id === "url") {
    content = (
      <form className="cs-modal-form" onSubmit={(e) => { e.preventDefault(); if (url.trim()) run(() => analyzeUrl(url.trim()), url.trim()); }}>
        <label>Suspicious URL</label>
        <div className="cs-modal-input"><LinkIcon /><input type="url" required value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com" /></div>
        <div className="cs-modal-actions"><button className="cs-modal-primary" type="submit" disabled={loading}>{loading ? "Analyzing…" : "Analyze URL"}<ArrowIcon /></button><span>ML + security heuristics</span></div>
      </form>
    );
  } else if (tool.id === "file") {
    content = (
      <form className="cs-modal-form" onSubmit={(e) => { e.preventDefault(); if (file) run(() => scanFile(file), file.name); }}>
        <label>Choose a file</label>
        <FileDrop file={file} setFile={setFile} />
        <div className="cs-modal-actions"><button className="cs-modal-primary" type="submit" disabled={loading || !file}>{loading ? "Scanning…" : "Scan File"}<ArrowIcon /></button><span>Secure local scan • Files are analyzed statically</span></div>
      </form>
    );
  } else if (tool.id === "qr") {
    content = (
      <form className="cs-modal-form" onSubmit={(e) => { e.preventDefault(); if (qr) run(() => scanQr(qr), qr.name); }}>
        <label>Choose a QR image</label>
        <FileDrop file={qr} setFile={setQr} accept="image/*" icon={QrIcon} title="Select a QR image to inspect" caption="The decoded destination is analyzed before you open it." />
        <div className="cs-modal-actions"><button className="cs-modal-primary" type="submit" disabled={loading || !qr}>{loading ? "Decoding…" : "Analyze QR"}<ArrowIcon /></button><span>Image → destination → risk assessment</span></div>
      </form>
    );
  } else if (tool.id === "email") {
    content = (
      <form className="cs-modal-form" onSubmit={(e) => { e.preventDefault(); run(() => analyzeEmail({ ...email, reply_to_email: email.reply_to_email.trim() || null }), email.subject || email.sender_email || "Email message"); }}>
        <div className="cs-form-grid">
          <label>Sender<input type="email" value={email.sender_email} onChange={(e) => setEmail(v => ({ ...v, sender_email: e.target.value }))} placeholder="sender@example.com" /></label>
          <label>Reply-To<input type="email" value={email.reply_to_email} onChange={(e) => setEmail(v => ({ ...v, reply_to_email: e.target.value }))} placeholder="optional@example.com" /></label>
        </div>
        <label>Subject<input value={email.subject} onChange={(e) => setEmail(v => ({ ...v, subject: e.target.value }))} placeholder="Email subject" /></label>
        <label>Message<textarea rows="5" value={email.body} onChange={(e) => setEmail(v => ({ ...v, body: e.target.value }))} placeholder="Paste suspicious email content…" /></label>
        <div className="cs-modal-actions"><button className="cs-modal-primary" type="submit" disabled={loading}>{loading ? "Analyzing…" : "Analyze Email"}<ArrowIcon /></button><span>Sender + reply-to + content signals</span></div>
      </form>
    );
  } else if (tool.id === "login") {
    content = (
      <form className="cs-modal-form" onSubmit={(e) => { e.preventDefault(); run(() => analyzeLogin(login), login.user_identifier || login.ip_address || "Login activity"); }}>
        <div className="cs-form-grid">
          <label>User identifier<input required value={login.user_identifier} onChange={(e) => setLogin(v => ({ ...v, user_identifier: e.target.value }))} placeholder="user001" /></label>
          <label>IP address<input required value={login.ip_address} onChange={(e) => setLogin(v => ({ ...v, ip_address: e.target.value }))} placeholder="192.168.1.10" /></label>
          <label>Failed attempts<input type="number" min="0" value={login.failed_attempts} onChange={(e) => setLogin(v => ({ ...v, failed_attempts: Number(e.target.value) }))} /></label>
          <label>Login hour<input type="number" min="0" max="23" value={login.login_hour} onChange={(e) => setLogin(v => ({ ...v, login_hour: Number(e.target.value) }))} /></label>
        </div>
        <div className="cs-check-row">
          <label><input type="checkbox" checked={login.new_device} onChange={(e) => setLogin(v => ({ ...v, new_device: e.target.checked }))} />New or unknown device</label>
          <label><input type="checkbox" checked={login.unusual_location} onChange={(e) => setLogin(v => ({ ...v, unusual_location: e.target.checked }))} />Unusual location</label>
        </div>
        <div className="cs-modal-actions"><button className="cs-modal-primary" type="submit" disabled={loading}>{loading ? "Checking…" : "Analyze Login"}<ArrowIcon /></button><span>Transparent risk scoring</span></div>
      </form>
    );
  } else if (tool.id === "threats") {
    content = (
      <div className="cs-info-modal">
        {[
          ["URL Engine", "ML classification plus URL structure and heuristic indicators."],
          ["File Scanner", "Static file inspection; uploaded files are not executed."],
          ["Email Signals", "Sender, reply-to, subject and message patterns."],
          ["Login Risk", "Failed attempts, device novelty, location and login time."]
        ].map(([title, description]) => <article key={title}><DatabaseIcon /><div><strong>{title}</strong><p>{description}</p></div></article>)}
      </div>
    );
  } else {
    content = (
      <div className="cs-awareness-modal">
        {[
          ["Verify links", "Check the real destination before entering passwords or payment details."],
          ["Treat QR codes like links", "Preview unknown QR destinations before opening them."],
          ["Be careful with attachments", "Unexpected executables, archives and macro files deserve extra review."],
          ["Use MFA", "Enable multi-factor authentication on important accounts."],
          ["Review login alerts", "Unexpected device or location alerts should be investigated quickly."],
          ["Question urgency", "Pressure and artificial deadlines are common social-engineering tactics."]
        ].map(([title, description], index) => <article key={title}><span>{String(index + 1).padStart(2, "0")}</span><div><strong>{title}</strong><p>{description}</p></div></article>)}
      </div>
    );
  }

  return (
    <div className="cs-modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <section className={`cs-tool-modal modal-${tool.id}`}>
        <header>
          <span className={`cs-modal-icon tone-${tool.tone}`}><Icon /></span>
          <div><small>CYBERSHIELD TOOL</small><h2>{tool.title}</h2></div>
          <button className="cs-modal-close" onClick={onClose}><CloseIcon /></button>
        </header>
        <div className="cs-modal-body">
          {content}
          <CompactResult result={result} error={error} loading={loading} />
        </div>
      </section>
    </div>
  );
}

export default function App() {
  const rootRef = useRef(null);
  useMouseFlow(rootRef);

  const [activeTool, setActiveTool] = useState(null);
  const [stats, setStats] = useState(null);
  const [online, setOnline] = useState(false);
  const [history, setHistory] = useState([]);

  useEffect(() => {
    let alive = true;
    getPublicStats()
      .then((data) => { if (alive) { setStats(data); setOnline(true); } })
      .catch(() => { if (alive) setOnline(false); });
    return () => { alive = false; };
  }, []);

  const tool = useMemo(() => tools.find((item) => item.id === activeTool) || null, [activeTool]);

  function select(id) {
    if (id === "home") {
      setActiveTool(null);
      window.scrollTo({ top: 0, behavior: "smooth" });
      return;
    }
    if (id === "history") {
      document.getElementById("history-section")?.scrollIntoView({ behavior: "smooth", block: "end" });
      return;
    }
    setActiveTool(id);
  }

  function record(entry) {
    setHistory((items) => [entry, ...items].slice(0, 20));
  }

  return (
    <div ref={rootRef} className="cs-page">
      <BackgroundMotion />
      <Header online={online} onSelect={select} />

      <main className="cs-shell">
        <Hero onOpen={setActiveTool} />
        <ToolCards onOpen={setActiveTool} />
        <BottomDashboard stats={stats} history={history} />
      </main>

      <div className="cs-api-foot">API {API_BASE_URL}</div>
      {tool && <ToolModal tool={tool} onClose={() => setActiveTool(null)} onRecord={record} />}
    </div>
  );
}
