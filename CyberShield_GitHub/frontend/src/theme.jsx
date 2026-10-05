import React, { useEffect, useMemo, useRef, useState } from "react";

export const THEME_KEY = "cybershield_theme_preference";
export const THEME_OPTIONS = ["system", "light", "dark"];

function safePreference(value) {
  return THEME_OPTIONS.includes(value) ? value : "system";
}

export function resolveTheme(preference) {
  if (preference === "light" || preference === "dark") return preference;
  if (typeof window === "undefined" || !window.matchMedia) return "light";
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function updateThemeColor(theme) {
  if (typeof document === "undefined") return;
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", theme === "dark" ? "#07090f" : "#ffffff");
}

export function applyTheme(preference) {
  if (typeof document === "undefined") return "light";
  const safe = safePreference(preference);
  const resolved = resolveTheme(safe);
  document.documentElement.dataset.theme = resolved;
  document.documentElement.dataset.themePreference = safe;
  document.documentElement.style.colorScheme = resolved;
  updateThemeColor(resolved);
  return resolved;
}

export function useThemePreference() {
  const [preference, setPreferenceState] = useState(() => {
    if (typeof window === "undefined") return "system";
    return safePreference(window.localStorage.getItem(THEME_KEY));
  });
  const [resolvedTheme, setResolvedTheme] = useState(() => resolveTheme(preference));

  useEffect(() => {
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const sync = () => setResolvedTheme(applyTheme(preference));
    sync();
    if (preference === "system") media.addEventListener?.("change", sync);
    return () => media.removeEventListener?.("change", sync);
  }, [preference]);

  const setPreference = value => {
    const safe = safePreference(value);
    window.localStorage.setItem(THEME_KEY, safe);
    setPreferenceState(safe);
  };

  return { preference, setPreference, resolvedTheme };
}

function ThemeGlyph({ type }) {
  if (type === "light") {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.42-1.41M17.66 6.34l1.41-1.41"/></svg>
    );
  }
  if (type === "dark") {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20.1 15.4A8.4 8.4 0 0 1 8.6 3.9 8.6 8.6 0 1 0 20.1 15.4Z"/></svg>
    );
  }
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
  );
}

const labels = { system: "System", light: "Light", dark: "Dark" };

export function ThemeControl({ preference, setPreference, resolvedTheme, compact = false, className = "" }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    const close = event => {
      if (!ref.current?.contains(event.target)) setOpen(false);
    };
    const escape = event => { if (event.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", escape);
    };
  }, [open]);

  const activeIcon = preference === "system" ? "system" : resolvedTheme;
  const status = useMemo(() => preference === "system" ? `System · ${resolvedTheme}` : labels[preference], [preference, resolvedTheme]);

  return (
    <div className={`theme-control ${compact ? "is-compact" : ""} ${className}`} ref={ref}>
      <button
        className="theme-trigger"
        type="button"
        onClick={() => setOpen(value => !value)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Appearance: ${status}`}
        title={`Appearance: ${status}`}
      >
        <span className="theme-trigger-icon"><ThemeGlyph type={activeIcon} /></span>
        {!compact && <span className="theme-trigger-label">{status}</span>}
        <span className="theme-trigger-chevron">⌄</span>
      </button>
      {open && (
        <div className="theme-menu" role="menu" aria-label="Appearance">
          <div className="theme-menu-title"><strong>Appearance</strong><small>Choose how CyberShield looks</small></div>
          {THEME_OPTIONS.map(option => (
            <button
              key={option}
              type="button"
              role="menuitemradio"
              aria-checked={preference === option}
              className={`theme-option ${preference === option ? "is-selected" : ""}`}
              onClick={() => { setPreference(option); setOpen(false); }}
            >
              <span className="theme-option-icon"><ThemeGlyph type={option} /></span>
              <span className="theme-option-copy">
                <strong>{labels[option]}</strong>
                <small>{option === "system" ? "Follow your Mac / device setting" : option === "light" ? "Always use light appearance" : "Always use dark appearance"}</small>
              </span>
              <span className="theme-option-check">{preference === option ? "✓" : ""}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
