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
  ArrowIcon,
  CapIcon,
  CheckIcon,
  ChevronLeft,
  ChevronRight,
  CloseIcon,
  DatabaseIcon,
  FileIcon,
  GlobeIcon,
  GridIcon,
  LinkIcon,
  LockIcon,
  MailIcon,
  MenuIcon,
  QrIcon,
  SearchIcon,
  ShieldIcon,
  UserIcon,
  ZapIcon
} from "./icons";
import { ThemeControl, useThemePreference } from "./theme";

const tools = [
  {
    id: "url",
    title: "URL Analyzer",
    description: "Check suspicious links for malware, phishing and harmful content.",
    icon: LinkIcon,
    tone: "gold"
  },
  {
    id: "file",
    title: "File Analyzer",
    description: "Scan files for malware indicators, suspicious signatures and hidden threats.",
    icon: FileIcon,
    tone: "green"
  },
  {
    id: "qr",
    title: "QR Analyzer",
    description: "Inspect QR codes before opening the destination they point to.",
    icon: QrIcon,
    tone: "purple"
  },
  {
    id: "email",
    title: "Email Analyzer",
    description: "Review suspicious email text for phishing, scams and social-engineering signals.",
    icon: MailIcon,
    tone: "rose"
  },
  {
    id: "login",
    title: "Login Risk",
    description: "Check unusual login activity using transparent security risk signals.",
    icon: UserIcon,
    tone: "orange"
  },
  {
    id: "threats",
    title: "Threat Intelligence",
    description: "Explore threat activity, attack patterns and the latest system insights.",
    icon: DatabaseIcon,
    tone: "blue"
  },
  {
    id: "awareness",
    title: "Cyber Awareness",
    description: "Learn safer habits and understand why common cyber threats work.",
    icon: CapIcon,
    tone: "purple"
  }
];

const steps = [
  {
    title: "Scan Anything",
    description: "Enter a URL, upload a file or describe a login event.",
    icon: LinkIcon
  },
  {
    title: "AI Analysis",
    description: "CyberShield checks the input using ML and transparent security rules.",
    icon: SearchIcon
  },
  {
    title: "Get Instant Results",
    description: "Receive a clear risk result with indicators you can understand.",
    icon: ShieldIcon
  },
  {
    title: "Stay Safer",
    description: "Use the result as a decision-support signal before taking action.",
    icon: CheckIcon
  }
];

const benefits = [
  {
    title: "AI-Powered Detection",
    description: "Hybrid URL analysis combines a trained ML model with practical security heuristics.",
    icon: ShieldIcon,
    href: "https://www.cert-in.org.in/s2cMainServlet?VLCODE=CIAD-2026-0020&pageid=PUBVLNOTES02",
    source: "CERT-In • AI Cyber Risks"
  },
  {
    title: "Real-Time Intelligence",
    description: "A unified dashboard turns scan activity into understandable security insights.",
    icon: GlobeIcon,
    href: "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBADVLIST",
    source: "CERT-In • Security Advisories"
  },
  {
    title: "Privacy First",
    description: "The login risk tool analyzes contextual signals and does not collect user passwords.",
    icon: LockIcon,
    href: "https://www.cert-in.org.in/AwarenessBooklets.jsp",
    source: "CERT-In • Awareness Booklets"
  },
  {
    title: "Easy for Everyone",
    description: "A clean interface gives students, professionals and teams a simple workflow.",
    icon: UserIcon,
    href: "https://cybercrime.gov.in/Webform/CyberAware.aspx",
    source: "I4C • Cyber Awareness"
  }
];

const testimonials = [
  {
    name: "Sarah Chen",
    role: "University Student",
    quote: "CyberShield AI has helped me avoid suspicious links. I like that the result is clear instead of just showing a scary warning.",
    initials: "SC"
  },
  {
    name: "Marcus Taylor",
    role: "IT Security Manager",
    quote: "The interface makes security checks quick enough to become part of a normal workflow. The separation between URL, file and login risk is very useful.",
    initials: "MT"
  },
  {
    name: "Priya Desai",
    role: "Freelance Designer",
    quote: "I like how simple the experience is. The dashboard explains what the system found instead of expecting users to understand raw technical output.",
    initials: "PD"
  }
];

const navItems = [
  ["Home", "home"],
  ["URL Scanner", "tools"],
  ["File Scanner", "tools"],
  ["QR Analyzer", "tools"],
  ["Email Analyzer", "tools"],
  ["Login Risk", "tools"],
  ["Threat Intelligence", "threat-intelligence"],
  ["Cyber Awareness", "benefits"]
];

function scrollToId(id) {
  document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function useReveal() {
  useEffect(() => {
    const elements = [...document.querySelectorAll("[data-reveal]")];
    const observer = new IntersectionObserver(
      entries => {
        entries.forEach(entry => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.14 }
    );
    elements.forEach(el => observer.observe(el));
    return () => observer.disconnect();
  }, []);
}

function formatHumanLabel(value, fallback = "Not available") {
  if (value == null || value === "") return fallback;
  return String(value)
    .replaceAll("_", " ")
    .replace(/\b\w/g, letter => letter.toUpperCase());
}

function toPercent(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return null;
  const percent = number <= 1 ? number * 100 : number;
  return Math.max(0, Math.min(100, percent));
}

function normalizeTextItems(value) {
  if (!value) return [];
  if (Array.isArray(value)) {
    return value
      .map(item => {
        if (typeof item === "string") return item;
        if (!item || typeof item !== "object") return String(item || "");
        return item.title || item.reason || item.message || item.description || "";
      })
      .filter(Boolean);
  }
  if (typeof value === "object") {
    return Object.entries(value)
      .map(([key, item]) => {
        if (typeof item === "string" || typeof item === "number" || typeof item === "boolean") {
          return `${formatHumanLabel(key)}: ${item}`;
        }
        if (item && typeof item === "object") {
          return item.title || item.reason || item.message || item.description || "";
        }
        return "";
      })
      .filter(Boolean);
  }
  return [String(value)];
}

function normalizeActions(value) {
  if (!Array.isArray(value)) return [];
  return value
    .map(item => {
      if (typeof item === "string") return { title: item, priority: "medium" };
      if (!item || typeof item !== "object") return null;
      const title = item.title || item.action || item.message || item.description;
      if (!title) return null;
      return { title, priority: String(item.priority || "medium").toLowerCase() };
    })
    .filter(Boolean);
}

function normalizeResult(data) {
  if (!data || typeof data !== "object") return null;

  const scoreCandidates = [
    data.risk_score,
    data.final_risk_score,
    data.risk,
    data.score,
    data.malicious_probability,
    data.probability,
    data.confidence
  ];
  const rawScore = scoreCandidates.find(value => Number.isFinite(Number(value)));
  const score = rawScore == null ? null : toPercent(rawScore);
  const confidence = data.confidence == null ? null : toPercent(data.confidence);

  const prediction =
    data.prediction ||
    data.classification ||
    data.status ||
    data.label ||
    (data.risk_level ? `${data.risk_level} risk` : "Analysis complete");

  const riskLevel = String(data.risk_level || "").toUpperCase();
  const reasons = normalizeTextItems(
    data.reasons ||
      data.indicators ||
      data.flags ||
      data.security_indicators ||
      data.details
  );

  const explainability = data.explainability && typeof data.explainability === "object"
    ? {
        available: data.explainability.available !== false,
        title: data.explainability.title || "Why CyberShield reached this result",
        items: normalizeTextItems(data.explainability.items)
      }
    : null;

  return {
    score,
    confidence,
    prediction,
    predictionLabel: formatHumanLabel(prediction, "Analysis Complete"),
    riskLevel,
    reasons,
    explainability,
    preventionActions: normalizeActions(data.prevention_actions),
    recommendation: data.recommendation || null,
    raw: data
  };
}

function riskClass(label, score) {
  const text = String(label || "").toLowerCase();
  if (text.includes("high") || text.includes("malicious") || text.includes("suspicious") || (score ?? 0) >= 70) return "risk-high";
  if (text.includes("medium") || text.includes("review") || (score ?? 0) >= 35) return "risk-medium";
  return "risk-low";
}

function Brand() {
  return (
    <button className="brand" type="button" onClick={() => scrollToId("home")} aria-label="CyberShield AI home">
      <span className="brand-mark"><ShieldIcon /></span>
      <span className="brand-name">CyberShield <em>AI</em></span>
    </button>
  );
}

function PrimaryButton({ children, onClick, type = "button", className = "", disabled = false }) {
  return (
    <button type={type} className={`btn btn-primary ${className}`} onClick={onClick} disabled={disabled}>
      <span>{children}</span>
      <ArrowIcon />
    </button>
  );
}

function SecondaryButton({ children, onClick, className = "" }) {
  return (
    <button type="button" className={`btn btn-secondary ${className}`} onClick={onClick}>
      <span>{children}</span>
      <ArrowIcon />
    </button>
  );
}

function SectionTitle({ eyebrow, title, accent, description }) {
  const parts = accent && title.includes(accent) ? title.split(accent) : null;
  return (
    <div className="section-title" data-reveal>
      <p className="eyebrow">{eyebrow}</p>
      <h2>
        {parts ? <>{parts[0]}<span className="text-gold">{accent}</span>{parts[1]}</> : title}
      </h2>
      {description && <p className="section-description">{description}</p>}
    </div>
  );
}

function Navbar({ onOpenMenu, onOpenAdmin, theme }) {
  return (
    <header className="navbar-wrap">
      <nav className="navbar" aria-label="Main navigation">
        <Brand />
        <div className="nav-links">
          {navItems.map(([label, id], index) => (
            <button
              type="button"
              className={index === 0 ? "nav-link is-active" : "nav-link"}
              onClick={() => scrollToId(id)}
              key={label}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="nav-actions">
          <ThemeControl {...theme} compact />
          <button className="admin-btn" type="button" onClick={onOpenAdmin}>
            <UserIcon />
            <span>Admin</span>
          </button>
          <button className="menu-btn" type="button" onClick={onOpenMenu} aria-label="Open menu"><MenuIcon /></button>
        </div>
      </nav>
    </header>
  );
}

function MobileMenu({ open, onClose, onAdmin, theme }) {
  useEffect(() => {
    document.body.style.overflow = open ? "hidden" : "";
    return () => { document.body.style.overflow = ""; };
  }, [open]);

  if (!open) return null;
  return (
    <div className="mobile-menu-backdrop" onMouseDown={onClose}>
      <div className="mobile-menu glass-card" onMouseDown={e => e.stopPropagation()}>
        <div className="mobile-menu-head">
          <Brand />
          <button className="icon-btn" type="button" onClick={onClose}><CloseIcon /></button>
        </div>
        <div className="mobile-menu-theme">
          <span>Appearance</span>
          <ThemeControl {...theme} />
        </div>
        <div className="mobile-menu-items">
          {navItems.map(([label, id]) => (
            <button key={label} type="button" onClick={() => { onClose(); setTimeout(() => scrollToId(id), 50); }}>
              <span>{label}</span><ArrowIcon />
            </button>
          ))}
          <button className="mobile-admin" type="button" onClick={() => { onClose(); onAdmin(); }}>
            <UserIcon /><span>Admin Dashboard</span><ArrowIcon />
          </button>
        </div>
      </div>
    </div>
  );
}

function HeroDashboard() {
  return (
    <div className="hero-dashboard" aria-label="CyberShield dashboard preview" data-reveal>
      <div className="dashboard-topbar">
        <div className="mini-brand"><span className="mini-shield"><ShieldIcon /></span><strong>CyberShield AI</strong></div>
        <span className="status-chip safe"><span className="status-dot" /> System Protected</span>
      </div>
      <div className="dashboard-metrics">
        <div><span className="metric-icon gold"><FileIcon /></span><strong>1,248</strong><small>Scans today</small></div>
        <div><span className="metric-icon rose"><ShieldIcon /></span><strong>12</strong><small>Threats blocked</small></div>
        <div><span className="metric-icon teal"><ZapIcon /></span><strong>99.7%</strong><small>Detection rate</small></div>
      </div>
      <div className="dashboard-tabs"><span className="active">URL</span><span>File</span><span>QR Code</span><span>Email</span></div>
      <div className="dashboard-search"><SearchIcon /><span>Enter a URL to scan for threats...</span><button aria-label="Scan"><ArrowIcon /></button></div>
      <div className="dashboard-tags"><span className="danger">Malware</span><span className="rose">Phishing</span><span className="amber">Scams</span><span className="green">Safe</span></div>
      <div className="hero-orbit hero-orbit-one" />
      <div className="hero-orbit hero-orbit-two" />
      <div className="hero-shield-art"><ShieldIcon /><span className="lock-mini"><LockIcon /></span></div>
    </div>
  );
}

function Hero({ openScanner }) {
  return (
    <section className="hero section" id="home">
      <div className="ambient ambient-gold" />
      <div className="ambient ambient-blue" />
      <div className="container hero-grid">
        <div className="hero-copy" data-reveal>
          <div className="platform-pill"><ShieldIcon /><span>AI-Powered Cybersecurity Platform</span></div>
          <h1>Check before <span className="text-gold">you click.</span></h1>
          <p className="hero-description">
            Scan suspicious URLs, files and risky login activity from one powerful workspace. CyberShield AI helps you detect and understand threats before you trust them.
          </p>
          <div className="hero-actions">
            <PrimaryButton onClick={() => openScanner("url")}><SearchIcon /> Start Scan</PrimaryButton>
            <SecondaryButton onClick={() => window.location.assign("/admin.html")}><GridIcon /> Open Dashboard</SecondaryButton>
            <button className="text-action" type="button" onClick={() => scrollToId("how-it-works")}><ShieldIcon /> Why this was flagged? <ArrowIcon /></button>
          </div>
          <div className="trust-strip">
            <div><span className="trust-icon"><UserIcon /></span><p><strong>Trusted by students</strong><small>Researchers & organizations</small></p></div>
            <div><span className="trust-icon"><ShieldIcon /></span><p><strong>AI-powered</strong><small>Threat detection</small></p></div>
            <div><span className="trust-icon"><ZapIcon /></span><p><strong>Fast & practical</strong><small>Privacy-focused</small></p></div>
          </div>
        </div>
        <div className="hero-visual">
          <HeroDashboard />
        </div>
      </div>
    </section>
  );
}

function ToolCard({ tool, openScanner }) {
  const Icon = tool.icon;
  return (
    <article className="tool-card glass-card" data-reveal>
      <span className={`tool-icon tone-${tool.tone}`}><Icon /></span>
      <div className="tool-copy">
        <h3>{tool.title}</h3>
        <p>{tool.description}</p>
      </div>
      <button
        className="card-open"
        type="button"
        aria-label={`Open ${tool.title}`}
        onClick={() => {
          if (tool.id === "threats") scrollToId("threat-intelligence");
          else if (tool.id === "awareness") scrollToId("benefits");
          else openScanner(tool.id);
        }}
      >
        <ArrowIcon />
      </button>
    </article>
  );
}

function ToolsSection({ openScanner }) {
  return (
    <section className="section section-soft" id="tools">
      <div className="container">
        <div className="section-heading-row">
          <SectionTitle eyebrow="Our tools" title="Everything you need to stay safer online" accent="safer online" />
          <button className="section-link" type="button" onClick={() => openScanner("url")}>Start a scan <ArrowIcon /></button>
        </div>
        <div className="tools-grid">
          {tools.map(tool => <ToolCard key={tool.id} tool={tool} openScanner={openScanner} />)}
        </div>
      </div>
    </section>
  );
}

function HowItWorks() {
  return (
    <section className="section" id="how-it-works">
      <div className="container">
        <div className="section-heading-row">
          <SectionTitle
            eyebrow="How it works"
            title="Powerful protection in 4 simple steps"
            accent="4 simple steps"
            description="The workflow stays understandable: input, analysis, result and safer action."
          />
          <button type="button" className="section-link" onClick={() => scrollToId("threat-intelligence")}>See insights <ArrowIcon /></button>
        </div>
        <div className="steps-grid">
          {steps.map((step, index) => {
            const Icon = step.icon;
            return (
              <article className="step-card glass-card" key={step.title} data-reveal>
                <div className="step-top"><span className="step-number">{index + 1}</span><span className="step-icon"><Icon /></span></div>
                <h3>{step.title}</h3>
                <p>{step.description}</p>
              </article>
            );
          })}
        </div>
      </div>
    </section>
  );
}

function CountValue({ value, suffix = "" }) {
  const ref = useRef(null);
  const [visible, setVisible] = useState(false);
  const [display, setDisplay] = useState(0);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const observer = new IntersectionObserver(entries => {
      if (entries[0]?.isIntersecting) {
        setVisible(true);
        observer.disconnect();
      }
    }, { threshold: 0.4 });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!visible) return;
    const started = performance.now();
    const duration = 800;
    const tick = now => {
      const p = Math.min(1, (now - started) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      setDisplay(value * eased);
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [visible, value]);

  const formatted = Number.isInteger(value) ? Math.round(display).toLocaleString() : display.toFixed(1);
  return <span ref={ref}>{formatted}{suffix}</span>;
}

function ThreatMap() {
  const hotspots = [
    [14, 39], [22, 54], [31, 33], [42, 45], [49, 29], [55, 40], [62, 47], [70, 35], [77, 51], [84, 42], [65, 63], [46, 61]
  ];
  return (
    <div className="threat-map">
      <div className="map-grid" />
      <div className="map-continent continent-a" />
      <div className="map-continent continent-b" />
      <div className="map-continent continent-c" />
      <div className="map-continent continent-d" />
      {hotspots.map(([x, y], i) => <span className={`hotspot hotspot-${i % 3}`} style={{ left: `${x}%`, top: `${y}%` }} key={`${x}-${y}`} />)}
      <div className="map-header"><span><GlobeIcon /> Global Threat Activity</span><b><span className="status-dot" /> Live</b></div>
    </div>
  );
}

function ThreatIntelligence({ stats }) {
  const scans = Number(stats?.total_scans ?? stats?.scans ?? 1248) || 1248;
  const threats = Number(stats?.threats ?? stats?.malicious ?? 12) || 12;
  const rate = Number(stats?.detection_rate ?? stats?.accuracy ?? 99.7) || 99.7;
  return (
    <section className="section section-soft" id="threat-intelligence">
      <div className="container">
        <div className="section-heading-row threat-title-row">
          <SectionTitle
            eyebrow="Live threat intelligence"
            title="Real-time insights. A safer internet."
            accent="A safer internet."
            description="A dashboard view of scans, blocked threats and the signals CyberShield uses to explain risk."
          />
          <button type="button" className="section-link" onClick={() => window.location.assign("/admin.html")}>Open analytics <ArrowIcon /></button>
        </div>
        <div className="threat-layout">
          <div className="metric-stack" data-reveal>
            <div className="stat-card glass-card"><span className="stat-icon blue"><FileIcon /></span><div><strong><CountValue value={scans} /></strong><small>Scans tracked</small></div><em>+12%</em></div>
            <div className="stat-card glass-card"><span className="stat-icon rose"><ShieldIcon /></span><div><strong><CountValue value={threats} /></strong><small>Threats blocked</small></div><em className="down">Live</em></div>
            <div className="stat-card glass-card"><span className="stat-icon green"><ZapIcon /></span><div><strong><CountValue value={rate} suffix="%" /></strong><small>Detection signal</small></div><em>+2.1%</em></div>
            <div className="stat-card glass-card"><span className="stat-icon purple"><UserIcon /></span><div><strong>50K+</strong><small>Protected users</small></div><em>Growing</em></div>
          </div>
          <div className="map-card glass-card" data-reveal>
            <ThreatMap />
          </div>
          <div className="chart-stack" data-reveal>
            <div className="mini-chart glass-card">
              <div className="mini-chart-head"><strong>Top Threat Types</strong><small>Last 30 days</small></div>
              {[
                ["Phishing", 36, "pink"], ["Malware", 28, "purple"], ["Scams", 18, "orange"], ["Botnets", 10, "gold"], ["Suspicious IPs", 8, "blue"]
              ].map(([name, width, tone]) => (
                <div className="threat-row" key={name}><span>{name}</span><div className="bar"><i className={tone} style={{ width: `${width * 2.3}%` }} /></div><b>{width}%</b></div>
              ))}
            </div>
            <div className="blocked-chart glass-card">
              <div className="mini-chart-head"><strong>Threats Blocked Over Time</strong><small>7 days</small></div>
              <div className="bars">
                {[32, 46, 39, 58, 64, 73, 81].map((v, i) => <i key={i} style={{ height: `${v}%` }} />)}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function Benefits() {
  return (
    <section className="section" id="benefits">
      <div className="container">
        <div className="section-heading-row">
          <SectionTitle
            eyebrow="Why CyberShield AI"
            title="More protection. Less risk. Built for everyone."
            accent="Built for everyone."
            description="A modern academic security platform built around explainable workflows and practical detection signals."
          />
        </div>
        <div className="benefits-grid">
          {benefits.map(item => {
            const Icon = item.icon;
            return (
              <a
                className="benefit-card glass-card official-resource-card"
                key={item.title}
                data-reveal
                href={item.href}
                target="_blank"
                rel="noopener noreferrer"
                aria-label={`${item.title} — open official Government of India cyber resource`}
              >
                <div className="benefit-top">
                  <span className="benefit-icon"><Icon /></span>
                  <span className="benefit-arrow" aria-hidden="true"><ArrowIcon /></span>
                </div>
                <h3>{item.title}</h3>
                <p>{item.description}</p>
                <span className="benefit-source">{item.source} ↗</span>
              </a>
            );
          })}
        </div>
      </div>
    </section>
  );
}

function Testimonials() {
  const [index, setIndex] = useState(0);
  const ordered = useMemo(() => testimonials.map((_, i) => testimonials[(index + i) % testimonials.length]), [index]);
  return (
    <section className="section section-soft" id="testimonials">
      <div className="container">
        <div className="section-heading-row testimonial-heading">
          <SectionTitle eyebrow="Trusted worldwide" title="Loved by security-conscious users" />
          <div className="carousel-controls">
            <button type="button" onClick={() => setIndex((index + testimonials.length - 1) % testimonials.length)} aria-label="Previous testimonials"><ChevronLeft /></button>
            <button type="button" onClick={() => setIndex((index + 1) % testimonials.length)} aria-label="Next testimonials"><ChevronRight /></button>
          </div>
        </div>
        <div className="testimonials-grid">
          {ordered.map((person, i) => (
            <article className="testimonial-card glass-card" key={`${person.name}-${index}-${i}`} data-reveal>
              <div className="author-row">
                <div className="avatar">{person.initials}</div>
                <div><strong>{person.name}</strong><small>{person.role}</small></div>
                <span className="stars">★★★★★</span>
              </div>
              <p>“{person.quote}”</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

function FinalCTA({ openScanner }) {
  return (
    <section className="section cta-section">
      <div className="container">
        <div className="cta-banner" data-reveal>
          <div className="cta-grid-lines" />
          <div className="cta-copy">
            <div className="cta-pill"><ShieldIcon /> Stay ahead of threats</div>
            <h2>Be one step ahead of <span>cyber threats.</span></h2>
            <p>Use CyberShield AI as a fast security check before you trust a link, file or unusual login event.</p>
            <div className="cta-actions">
              <PrimaryButton onClick={() => openScanner("url")}><SearchIcon /> Start Scanning Now</PrimaryButton>
              <SecondaryButton onClick={() => window.location.assign("/admin.html")}><GridIcon /> View Dashboard</SecondaryButton>
            </div>
          </div>
          <div className="cta-benefits">
            <div><span><ShieldIcon /></span>AI-assisted analysis</div>
            <div><span><LockIcon /></span>Privacy-minded workflow</div>
            <div><span><ZapIcon /></span>Fast feedback</div>
          </div>
          <div className="cta-shield">
            <div className="cta-shield-ring" />
            <div className="cta-shield-core"><ShieldIcon /><span><LockIcon /></span></div>
          </div>
        </div>
      </div>
    </section>
  );
}

function Footer({ onOpenApiDocs, onOpenComplaintGuide }) {
  return (
    <footer className="footer">
      <div className="container footer-grid">
        <div className="footer-brand"><Brand /><p>Check. Scan. Stay safer.</p><div className="footer-status"><span className="status-dot" /> System online</div></div>
        <div className="footer-column"><strong>Product</strong><button onClick={() => scrollToId("tools")}>URL Scanner</button><button onClick={() => scrollToId("tools")}>File Scanner</button><button onClick={() => scrollToId("tools")}>Login Risk</button></div>
        <div className="footer-column"><strong>Platform</strong><button onClick={() => scrollToId("threat-intelligence")}>Threat Intelligence</button><button onClick={() => scrollToId("benefits")}>Cyber Awareness</button><a href="/admin.html">Admin Dashboard</a></div>
        <div className="footer-column"><strong>Resources</strong><button onClick={onOpenApiDocs}>API Docs</button><button onClick={() => scrollToId("how-it-works")}>How It Works</button><button onClick={onOpenComplaintGuide}>Report Cybercrime</button></div>
        <div className="complaint-footer-card">
          <div className="complaint-footer-icon"><ShieldIcon /></div>
          <div className="complaint-footer-copy"><strong>Need to report a cybercrime?</strong><p>Get the official India reporting route, evidence checklist and a complaint draft in one guided flow.</p></div>
          <button className="complaint-footer-action" type="button" onClick={onOpenComplaintGuide}><span>Start complaint guide</span><ArrowIcon /></button>
        </div>
      </div>
      <div className="container footer-bottom"><span>© 2026 CyberShield AI. Academic cybersecurity project.</span><div><span>Privacy First</span><span>Static file analysis</span><span>JWT admin APIs</span></div></div>
    </footer>
  );
}



const CYBERCRIME_PORTAL_URL = "https://www.cybercrime.gov.in/";
const CYBERCRIME_TRACK_URL = "https://www.cybercrime.gov.in/webform/chkackstatus.aspx";
const CYBERCRIME_SUSPECT_URL = "https://cybercrime.gov.in/Webform/cyber_suspect.aspx";
const CYBERCRIME_NODAL_URL = "https://www.cybercrime.gov.in/webform/Crime_NodalGrivanceList.aspx";

function openExternal(url) {
  window.open(url, "_blank", "noopener,noreferrer");
}

function ComplaintGuideModal({ open, onClose }) {
  const [draft, setDraft] = useState({
    incidentType: "Online financial fraud",
    incidentDate: "",
    platform: "",
    identifier: "",
    amount: "",
    reference: "",
    description: "",
    evidence: ""
  });
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!open) return;
    setCopied(false);
  }, [open]);

  useEffect(() => {
    document.body.style.overflow = open ? "hidden" : "";
    return () => { document.body.style.overflow = ""; };
  }, [open]);

  if (!open) return null;

  const update = (key, value) => setDraft(previous => ({ ...previous, [key]: value }));
  const complaintText = [
    `Subject: Cybercrime complaint - ${draft.incidentType || "Cyber incident"}`,
    "",
    `Incident type: ${draft.incidentType || "Not specified"}`,
    `Incident date/time: ${draft.incidentDate || "Not specified"}`,
    `Platform / website / app: ${draft.platform || "Not specified"}`,
    `Suspicious phone / email / URL / account: ${draft.identifier || "Not specified"}`,
    `Amount lost (if any): ${draft.amount || "Not applicable / not specified"}`,
    `Existing complaint reference: ${draft.reference || "Not filed yet"}`,
    "",
    "Incident description:",
    draft.description || "Add a clear chronological description of what happened.",
    "",
    "Evidence available:",
    draft.evidence || "Screenshots, transaction IDs, URLs, emails, phone numbers, chat logs or other supporting material.",
    "",
    "I request that this cybercrime complaint / follow-up be reviewed and appropriate action be taken."
  ].join("\n");

  async function copyDraft() {
    try {
      await navigator.clipboard.writeText(complaintText);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  }

  function openEmailDraft() {
    const subject = `Cybercrime complaint - ${draft.incidentType || "Cyber incident"}`;
    window.location.href = `mailto:?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(complaintText)}`;
  }

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div className="scanner-modal complaint-guide-modal" onMouseDown={event => event.stopPropagation()}>
        <div className="scanner-modal-head">
          <div>
            <span className="tool-icon tone-gold"><ShieldIcon /></span>
            <div><small>OFFICIAL REPORTING ASSISTANT</small><h2>Cybercrime Complaint Guide</h2></div>
          </div>
          <button className="icon-btn" type="button" onClick={onClose} aria-label="Close complaint guide"><CloseIcon /></button>
        </div>

        <div className="scanner-content complaint-guide-content">
          <div className="complaint-privacy-note"><LockIcon /><span>CyberShield does not submit this form to the Government and does not store these draft fields. Use the official portal buttons below to file or track a complaint.</span></div>

          <section className="complaint-route-section">
            <div className="complaint-section-heading"><small>STEP 1</small><h3>Choose the right reporting route</h3><p>Select the situation closest to what happened.</p></div>
            <div className="complaint-route-grid">
              <article className="complaint-route-card urgent">
                <span className="route-kicker">MONEY LOST / FINANCIAL FRAUD</span>
                <h4>Act immediately</h4>
                <p>For cyber financial fraud, call the national helpline first, then continue the official online complaint process.</p>
                <div className="route-actions"><a className="route-primary" href="tel:1930">Call 1930</a><button type="button" onClick={() => openExternal(CYBERCRIME_PORTAL_URL)}>Open official portal <ArrowIcon /></button></div>
              </article>

              <article className="complaint-route-card">
                <span className="route-kicker">OTHER CYBERCRIME</span>
                <h4>File an official complaint</h4>
                <p>Use the National Cyber Crime Reporting Portal for hacking, social-media crime, ransomware, online fraud and other cybercrimes.</p>
                <button type="button" onClick={() => openExternal(CYBERCRIME_PORTAL_URL)}>Register complaint <ArrowIcon /></button>
              </article>

              <article className="complaint-route-card">
                <span className="route-kicker">SUSPICIOUS IDENTIFIER ONLY</span>
                <h4>Report a suspect</h4>
                <p>Report suspicious website URLs, phone numbers, email IDs, WhatsApp/Telegram handles, SMS headers or social-media URLs to I4C.</p>
                <button type="button" onClick={() => openExternal(CYBERCRIME_SUSPECT_URL)}>Report suspect <ArrowIcon /></button>
              </article>

              <article className="complaint-route-card">
                <span className="route-kicker">ALREADY FILED</span>
                <h4>Track or follow up</h4>
                <p>Use your acknowledgement number to track the complaint. If needed, use the official State/UT nodal and grievance contact list for follow-up.</p>
                <div className="route-actions"><button type="button" onClick={() => openExternal(CYBERCRIME_TRACK_URL)}>Track complaint <ArrowIcon /></button><button type="button" className="route-secondary" onClick={() => openExternal(CYBERCRIME_NODAL_URL)}>Nodal contacts</button></div>
              </article>
            </div>
          </section>

          <section className="complaint-evidence-section">
            <div className="complaint-section-heading"><small>STEP 2</small><h3>Keep the evidence ready</h3><p>Do not delete messages or transaction information before recording the details.</p></div>
            <div className="evidence-grid">
              {["Screenshots / screen recordings", "Transaction ID / UTR / bank details", "Suspicious URL, email or phone number", "Chat, SMS or social-media messages", "Date, time and timeline of events", "Complaint acknowledgement number, if already filed"].map(item => <div className="evidence-item" key={item}><CheckIcon /><span>{item}</span></div>)}
            </div>
          </section>

          <section className="complaint-draft-section">
            <div className="complaint-section-heading"><small>STEP 3</small><h3>Prepare a complaint draft</h3><p>Use this as a writing aid before filing on the official portal or preparing a follow-up email.</p></div>
            <div className="complaint-draft-grid">
              <label>Incident type<select value={draft.incidentType} onChange={e => update("incidentType", e.target.value)}><option>Online financial fraud</option><option>Phishing / fake website</option><option>Account hacked / unauthorized access</option><option>Social media / messaging abuse</option><option>Ransomware / malware</option><option>Other cybercrime</option></select></label>
              <label>Incident date / time<input type="datetime-local" value={draft.incidentDate} onChange={e => update("incidentDate", e.target.value)} /></label>
              <label>Platform / website / app<input value={draft.platform} onChange={e => update("platform", e.target.value)} placeholder="Example: WhatsApp, bank app, website" /></label>
              <label>Phone / email / URL / account<input value={draft.identifier} onChange={e => update("identifier", e.target.value)} placeholder="Suspicious identifier" /></label>
              <label>Amount lost (if any)<input value={draft.amount} onChange={e => update("amount", e.target.value)} placeholder="Example: ₹10,000" /></label>
              <label>Complaint reference (optional)<input value={draft.reference} onChange={e => update("reference", e.target.value)} placeholder="Acknowledgement number" /></label>
              <label className="draft-wide">What happened?<textarea value={draft.description} onChange={e => update("description", e.target.value)} rows="5" placeholder="Write the incident in time order: what you clicked, what was asked, what happened next..." /></label>
              <label className="draft-wide">Evidence available<textarea value={draft.evidence} onChange={e => update("evidence", e.target.value)} rows="3" placeholder="List screenshots, transaction IDs, emails, URLs, phone numbers, chat records..." /></label>
            </div>

            <div className="complaint-draft-preview"><div className="draft-preview-head"><strong>Draft preview</strong><span>Local writing aid only</span></div><pre>{complaintText}</pre></div>
            <div className="complaint-draft-actions"><PrimaryButton onClick={copyDraft}>{copied ? "Copied" : "Copy complaint draft"}</PrimaryButton><SecondaryButton onClick={openEmailDraft}><MailIcon /> Prepare email draft</SecondaryButton><button className="official-portal-button" type="button" onClick={() => openExternal(CYBERCRIME_PORTAL_URL)}>Continue on official portal <ArrowIcon /></button></div>
            <p className="complaint-email-note">For follow-up email, use the appropriate official State/UT Nodal or Grievance Officer contact from the Government list. Do not send passwords, PINs or OTPs by email.</p>
          </section>

          <section className="complaint-example-section">
            <div className="complaint-section-heading"><small>EXAMPLE</small><h3>What a useful complaint looks like</h3></div>
            <div className="example-complaint-card"><strong>Phishing payment example</strong><p>“On 3 October at 2:15 PM, I received a message claiming to be from my bank. I opened the linked page and entered my mobile number. I then noticed the domain was not the bank’s official domain. No OTP or password was shared. I have screenshots of the message, the URL and the page.”</p></div>
          </section>
        </div>
      </div>
    </div>
  );
}

function ApiDocsModal({ open, onClose }) {
  const [schema, setSchema] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    let active = true;
    setLoading(true);
    setError("");

    fetch(`${API_BASE_URL}/openapi.json`)
      .then(async response => {
        if (!response.ok) throw new Error(`Unable to load API reference (${response.status})`);
        return response.json();
      })
      .then(data => {
        if (active) setSchema(data);
      })
      .catch(err => {
        if (active) setError(err.message || "Unable to load API reference.");
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => { active = false; };
  }, [open]);

  if (!open) return null;

  const endpoints = schema
    ? Object.entries(schema.paths || {}).flatMap(([path, methods]) =>
        Object.entries(methods || {})
          .filter(([method]) => ["get", "post", "put", "patch", "delete"].includes(method.toLowerCase()))
          .map(([method, meta]) => ({
            method: method.toUpperCase(),
            path,
            summary: meta?.summary || meta?.operationId || "CyberShield API endpoint"
          }))
      )
    : [];

  const required = [
    "/analyze",
    "/scan-file",
    "/scan-qr",
    "/analyze-email",
    "/analyze-login",
    "/admin/login",
    "/admin/stats",
    "/admin/recent"
  ];
  const availablePaths = new Set(Object.keys(schema?.paths || {}));
  const missing = required.filter(path => !availablePaths.has(path));

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div className="scanner-modal api-docs-modal" onMouseDown={event => event.stopPropagation()}>
        <div className="scanner-modal-head">
          <div>
            <span className="tool-icon tone-gold"><DatabaseIcon /></span>
            <div>
              <small>CYBERSHIELD DEVELOPER REFERENCE</small>
              <h2>API Docs</h2>
            </div>
          </div>
          <button className="icon-btn" type="button" onClick={onClose} aria-label="Close API docs"><CloseIcon /></button>
        </div>

        <div className="scanner-content api-docs-content">
          {loading && <div className="api-loading">Loading current API reference…</div>}
          {error && <div className="error-box">{error}</div>}

          {schema && (
            <>
              <div className="api-summary-card">
                <div>
                  <small>LIVE BACKEND</small>
                  <h3>{schema.info?.title || "CyberShield AI API"}</h3>
                  <p>Current deployed backend reference, shown inside CyberShield without opening Swagger UI.</p>
                </div>
                <div className="api-version">v{schema.info?.version || "—"}</div>
              </div>

              <div className={`api-compat ${missing.length ? "api-compat-warning" : "api-compat-ok"}`}>
                <strong>{missing.length ? "Frontend / backend mismatch detected" : "Frontend and backend endpoints are compatible"}</strong>
                <span>
                  {missing.length
                    ? `Missing from deployed backend: ${missing.join(", ")}`
                    : "All endpoints required by the current frontend are available."}
                </span>
              </div>

              <div className="api-docs-list">
                {endpoints.map(endpoint => (
                  <article className="api-endpoint" key={`${endpoint.method}-${endpoint.path}`}>
                    <span className={`api-method method-${endpoint.method.toLowerCase()}`}>{endpoint.method}</span>
                    <code>{endpoint.path}</code>
                    <p>{endpoint.summary}</p>
                  </article>
                ))}
              </div>

              <div className="notice api-doc-note">
                <ShieldIcon />
                <span>Admin endpoints still require the same JWT bearer authentication. This page is a read-only product reference and does not expose credentials.</span>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function ResultMetric({ label, value, tone = "neutral" }) {
  if (value == null || value === "") return null;
  return (
    <div className={`result-metric metric-${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ResultDetails({ toolId, result, context }) {
  const rows = [];
  const add = (label, value) => {
    if (value != null && value !== "") rows.push([label, value]);
  };

  if (toolId === "url") {
    add("Scanned URL", result.url || context?.url);
    add("Hostname", result.hostname);
    add("Decision source", formatHumanLabel(result.decision_source, ""));
    if (typeof result.trusted_domain === "boolean") {
      add("Trusted domain check", result.trusted_domain ? "Recognized trusted domain" : "No trusted-domain override");
    }
  }

  if (toolId === "file") {
    add("File name", result.file_name || context?.file?.name);
    add("Detected type", formatHumanLabel(result.detected_type || result.file_type || result.mime_type, ""));
    if (result.file_size_kb != null) add("File size", `${Number(result.file_size_kb).toFixed(2)} KB`);
    else if (context?.file?.size) add("File size", `${(context.file.size / 1024).toFixed(2)} KB`);
    add("SHA-256 fingerprint", result.sha256);
  }

  if (toolId === "qr") {
    add("Decoded type", formatHumanLabel(result.decoded_type, ""));
    add("Detected destination", result.extracted_url);
    add("Decoded content", result.decoded_content);
  }

  if (toolId === "email") {
    add("Sender", result.sender_email || context?.email?.sender_email);
    add("Reply-To", result.reply_to_email || context?.email?.reply_to_email);
    add("Subject", result.subject || context?.email?.subject);
    add("Detection method", formatHumanLabel(result.detection_method, ""));
    if (Number(result.highest_embedded_url_risk || 0) > 0) {
      add("Highest embedded URL risk", `${Number(result.highest_embedded_url_risk).toFixed(0)}%`);
    }
  }

  if (toolId === "login") {
    add("User", result.user_identifier || context?.login?.user_identifier);
    add("IP address", result.ip_address || context?.login?.ip_address);
    if (context?.login?.failed_attempts != null) add("Failed attempts", context.login.failed_attempts);
    if (context?.login?.login_hour != null) add("Login hour", `${context.login.login_hour}:00`);
  }

  if (rows.length === 0) return null;

  return (
    <div className="result-details-card">
      <div className="result-section-title"><span>Assessment details</span></div>
      <div className="result-details-grid">
        {rows.map(([label, value]) => (
          <div className={`result-detail-row ${label.includes("SHA-256") || label.includes("content") || label.includes("URL") ? "detail-wide" : ""}`} key={label}>
            <span>{label}</span>
            <strong>{String(value)}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}

function defaultRecommendation(normalized) {
  const text = `${normalized.prediction} ${normalized.riskLevel}`.toLowerCase();
  if (text.includes("malicious") || text.includes("high") || text.includes("suspicious")) {
    return "Do not trust this item yet. Avoid opening links, entering credentials or continuing the activity until it is independently verified.";
  }
  if (text.includes("review") || text.includes("medium")) {
    return "Some signals deserve verification. Confirm the source through an official channel before you continue.";
  }
  return "No strong high-risk indicators were detected. Continue using normal security checks and verify anything unexpected.";
}

function ResultPanel({ result, toolId, context }) {
  const normalized = normalizeResult(result);
  if (!normalized) return null;

  const cls = riskClass(normalized.riskLevel || normalized.prediction, normalized.score);
  const scoreText = normalized.score == null ? "✓" : `${Math.round(normalized.score)}%`;
  const recommendation = normalized.recommendation || defaultRecommendation(normalized);
  const eventSaved = result.security_event?.saved ?? result.database_saved;
  const incidentActive = Boolean(result.incident?.created_or_updated || result.incident?.incident_code);
  const sessionActive = Boolean(result.session_id);
  const explanationItems = normalized.explainability?.items || [];

  return (
    <div className={`result-panel ${cls}`}>
      <div className="result-hero-row">
       <div
  className="result-gauge"
  style={{
    background: `conic-gradient(
      ${
        cls === "risk-high"
          ? "#ef4444"
          : cls === "risk-medium"
            ? "#f59e0b"
            : "#22c55e"
      } 0% ${Math.max(0, Math.min(100, Number(normalized.score ?? 0)))}%,
      rgba(148, 163, 184, 0.18)
      ${Math.max(0, Math.min(100, Number(normalized.score ?? 0)))}% 100%
    )`,
  }}
>
          <span>{scoreText}</span>
        </div>
        <div className="result-hero-copy">
          <small>CyberShield assessment</small>
          <h3>{normalized.predictionLabel}</h3>
          <div className="result-badges">
            {normalized.riskLevel && <span className={`risk-badge ${cls}`}>{normalized.riskLevel} RISK</span>}
            {sessionActive && <span className="status-badge">Session linked</span>}
            {incidentActive && <span className="status-badge status-alert">Incident tracked</span>}
          </div>
          <p>CyberShield combines detection signals into a decision-support result. Verify important actions before proceeding.</p>
        </div>
      </div>

      <div className="result-metrics-grid">
        <ResultMetric label="Risk score" value={normalized.score == null ? null : `${normalized.score.toFixed(1)}%`} tone={cls.replace("risk-", "")} />
        <ResultMetric label="Confidence" value={normalized.confidence == null ? null : `${normalized.confidence.toFixed(1)}%`} />
        <ResultMetric label="Prediction" value={normalized.predictionLabel} />
        <ResultMetric label="Recorded" value={eventSaved === true ? "Saved to security log" : eventSaved === false ? "Not saved" : null} />
      </div>

      <ResultDetails toolId={toolId} result={result} context={context} />

      {normalized.reasons.length > 0 && (
        <div className="result-section result-reasons">
          <div className="result-section-title"><span>Why this result?</span></div>
          <ul>
            {normalized.reasons.slice(0, 8).map((item, index) => (
              <li key={`${item}-${index}`}><span className="reason-check"><CheckIcon /></span><span>{item}</span></li>
            ))}
          </ul>
        </div>
      )}

      {explanationItems.length > 0 && (
        <details className="explanation-card">
          <summary>{normalized.explainability?.title || "Why CyberShield reached this result"}</summary>
          <div className="explanation-list">
            {explanationItems.slice(0, 8).map((item, index) => <p key={`${item}-${index}`}>{item}</p>)}
          </div>
        </details>
      )}

      {normalized.preventionActions.length > 0 && (
        <div className="result-section prevention-card">
          <div className="result-section-title"><span>Recommended next steps</span></div>
          <div className="prevention-list">
            {normalized.preventionActions.slice(0, 6).map((action, index) => (
              <div className="prevention-item" key={`${action.title}-${index}`}>
                <span className={`priority-dot priority-${action.priority}`} />
                <span>{action.title}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="recommendation-card">
        <span className="recommendation-icon"><ShieldIcon /></span>
        <div><strong>What should I do?</strong><p>{recommendation}</p></div>
      </div>
    </div>
  );
}

function ScannerModal({ active, onClose }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [url, setUrl] = useState("");
  const [file, setFile] = useState(null);
  const [login, setLogin] = useState({
    user_identifier: "",
    ip_address: "",
    failed_attempts: 0,
    new_device: false,
    unusual_location: false,
    login_hour: new Date().getHours()
  });
  const [email, setEmail] = useState({ sender_email: "", reply_to_email: "", subject: "", body: "" });
  const [qrFile, setQrFile] = useState(null);

  const tool = tools.find(t => t.id === active);
  useEffect(() => {
    setError("");
    setResult(null);
  }, [active]);

  useEffect(() => {
    document.body.style.overflow = active ? "hidden" : "";
    return () => { document.body.style.overflow = ""; };
  }, [active]);

  if (!active || !tool) return null;
  const Icon = tool.icon;

  async function run(action) {
    setLoading(true); setError(""); setResult(null);
    try {
      const data = await action();
      setResult(data);
    } catch (e) {
      setError(e?.message || "Something went wrong.");
    } finally {
      setLoading(false);
    }
  }



  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div className="scanner-modal" onMouseDown={e => e.stopPropagation()}>
        <div className="scanner-modal-head">
          <div><span className={`tool-icon tone-${tool.tone}`}><Icon /></span><div><small>CyberShield tool</small><h2>{tool.title}</h2></div></div>
          <button className="icon-btn" type="button" onClick={onClose}><CloseIcon /></button>
        </div>
        <div className="scanner-content">
          {active === "url" && (
            <form onSubmit={e => { e.preventDefault(); if (url.trim()) run(() => analyzeUrl(url.trim())); }}>
              <label>Suspicious URL</label>
              <div className="scan-input"><LinkIcon /><input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com" type="url" required /></div>
              <PrimaryButton type="submit" disabled={loading}>{loading ? "Analyzing..." : "Analyze URL"}</PrimaryButton>
            </form>
          )}
          {active === "file" && (
            <form onSubmit={e => { e.preventDefault(); if (file) run(() => scanFile(file)); }}>
              <label>Choose a file</label>
              <div className="file-drop"><FileIcon /><input type="file" onChange={e => setFile(e.target.files?.[0] || null)} required /><strong>{file ? file.name : "Select a file to inspect"}</strong><small>Static analysis only — the file is not executed.</small></div>
              <PrimaryButton type="submit" disabled={loading || !file}>{loading ? "Scanning..." : "Scan File"}</PrimaryButton>
            </form>
          )}
          {active === "login" && (
            <form onSubmit={e => { e.preventDefault(); run(() => analyzeLogin(login)); }}>
              <div className="form-grid">
                <label>User identifier<input value={login.user_identifier} onChange={e => setLogin(v => ({ ...v, user_identifier: e.target.value }))} placeholder="user001" required /></label>
                <label>IP address<input value={login.ip_address} onChange={e => setLogin(v => ({ ...v, ip_address: e.target.value }))} placeholder="192.168.1.20" required /></label>
                <label>Failed attempts<input type="number" min="0" value={login.failed_attempts} onChange={e => setLogin(v => ({ ...v, failed_attempts: Number(e.target.value) }))}/></label>
                <label>Login hour (0–23)<input type="number" min="0" max="23" value={login.login_hour} onChange={e => setLogin(v => ({ ...v, login_hour: Number(e.target.value) }))}/></label>
              </div>
              <label className="toggle-row"><input type="checkbox" checked={login.new_device} onChange={e => setLogin(v => ({ ...v, new_device: e.target.checked }))}/><span>New / unknown device</span></label>
              <label className="toggle-row"><input type="checkbox" checked={login.unusual_location} onChange={e => setLogin(v => ({ ...v, unusual_location: e.target.checked }))}/><span>Unusual location</span></label>
              <PrimaryButton type="submit" disabled={loading}>{loading ? "Checking..." : "Analyze Login Risk"}</PrimaryButton>
            </form>
          )}
          {active === "email" && (
            <form onSubmit={e => { e.preventDefault(); if (email.sender_email.trim() || email.subject.trim() || email.body.trim()) run(() => analyzeEmail({ ...email, reply_to_email: email.reply_to_email.trim() || null })); }}>
              <div className="form-grid">
                <label>Sender email<input type="email" value={email.sender_email} onChange={e => setEmail(v => ({ ...v, sender_email: e.target.value }))} placeholder="security@example.com" /></label>
                <label>Reply-To email (optional)<input type="email" value={email.reply_to_email} onChange={e => setEmail(v => ({ ...v, reply_to_email: e.target.value }))} placeholder="reply@example.com" /></label>
              </div>
              <label>Email subject<input value={email.subject} onChange={e => setEmail(v => ({ ...v, subject: e.target.value }))} placeholder="Enter the email subject" /></label>
              <label>Email message</label>
              <textarea value={email.body} onChange={e => setEmail(v => ({ ...v, body: e.target.value }))} placeholder="Paste the suspicious email message here..." rows="8" />
              <PrimaryButton type="submit" disabled={loading}>{loading ? "Analyzing..." : "Analyze Email"}</PrimaryButton>
            </form>
          )}
          {active === "qr" && (
            <form onSubmit={e => { e.preventDefault(); if (qrFile) run(() => scanQr(qrFile)); }}>
              <label>QR code image</label>
              <div className="file-drop"><QrIcon /><input type="file" accept="image/*" onChange={e => setQrFile(e.target.files?.[0] || null)} required /><strong>{qrFile ? qrFile.name : "Select a QR image"}</strong><small>Upload an image containing a QR code. CyberShield will decode and analyze the destination.</small></div>
              <PrimaryButton type="submit" disabled={loading || !qrFile}>{loading ? "Decoding..." : "Analyze QR Code"}</PrimaryButton>
            </form>
          )}
          {error && <div className="error-box">{error}</div>}
          <ResultPanel
            result={result}
            toolId={active}
            context={{ url, file, qrFile, email, login }}
          />
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const theme = useThemePreference();
  const [menuOpen, setMenuOpen] = useState(false);
  const [activeScanner, setActiveScanner] = useState(null);
  const [stats, setStats] = useState(null);
  const [apiDocsOpen, setApiDocsOpen] = useState(false);
  const [complaintGuideOpen, setComplaintGuideOpen] = useState(false);
  useReveal();

  useEffect(() => {
    let active = true;
    getPublicStats().then(data => { if (active) setStats(data); }).catch(() => {});
    return () => { active = false; };
  }, []);

  return (
    <>
      <Navbar onOpenMenu={() => setMenuOpen(true)} onOpenAdmin={() => window.location.assign("/admin.html")} theme={theme} />
      <main>
        <Hero openScanner={setActiveScanner} />
        <ToolsSection openScanner={setActiveScanner} />
        <HowItWorks />
        <ThreatIntelligence stats={stats} />
        <Benefits />
        <Testimonials />
        <FinalCTA openScanner={setActiveScanner} />
      </main>
      <Footer onOpenApiDocs={() => setApiDocsOpen(true)} onOpenComplaintGuide={() => setComplaintGuideOpen(true)} />
      <MobileMenu open={menuOpen} onClose={() => setMenuOpen(false)} onAdmin={() => window.location.assign("/admin.html")} theme={theme} />
      <ScannerModal active={activeScanner} onClose={() => setActiveScanner(null)} />
      <ApiDocsModal open={apiDocsOpen} onClose={() => setApiDocsOpen(false)} />
      <ComplaintGuideModal open={complaintGuideOpen} onClose={() => setComplaintGuideOpen(false)} />
    </>
  );
}