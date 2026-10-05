import React from "react";

const common = {
  width: 22,
  height: 22,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.8,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  "aria-hidden": true
};

export const LinkIcon = () => <svg {...common}><path d="M10 13a5 5 0 0 0 7.5.5l2-2a5 5 0 0 0-7-7l-1.1 1.1"/><path d="M14 11a5 5 0 0 0-7.5-.5l-2 2a5 5 0 0 0 7 7l1.1-1.1"/></svg>;
export const FileIcon = () => <svg {...common}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h8M8 17h5"/></svg>;
export const QrIcon = () => <svg {...common}><path d="M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3z"/><path d="M14 14h3v3h-3zM18 18h3v3h-3zM18 14h3M14 18v3"/></svg>;
export const MailIcon = () => <svg {...common}><path d="M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z"/><path d="m22 6-10 7L2 6"/></svg>;
export const UserIcon = () => <svg {...common}><circle cx="12" cy="8" r="4"/><path d="M4 22a8 8 0 0 1 16 0"/></svg>;
export const DatabaseIcon = () => <svg {...common}><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/></svg>;
export const CapIcon = () => <svg {...common}><path d="m2 10 10-5 10 5-10 5z"/><path d="M6 12v5c3 2 9 2 12 0v-5"/><path d="M22 10v6"/></svg>;
export const ShieldIcon = () => <svg {...common}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>;
export const SearchIcon = () => <svg {...common}><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>;
export const GridIcon = () => <svg {...common}><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>;
export const ArrowIcon = () => <svg {...common} width="18" height="18"><path d="M5 12h14M13 6l6 6-6 6"/></svg>;
export const ChevronLeft = () => <svg {...common} width="18" height="18"><path d="m15 18-6-6 6-6"/></svg>;
export const ChevronRight = () => <svg {...common} width="18" height="18"><path d="m9 18 6-6-6-6"/></svg>;
export const MenuIcon = () => <svg {...common}><path d="M4 6h16M4 12h16M4 18h16"/></svg>;
export const CloseIcon = () => <svg {...common}><path d="M18 6 6 18M6 6l12 12"/></svg>;
export const ZapIcon = () => <svg {...common}><path d="M13 2 3 14h9l-1 8 10-12h-9z"/></svg>;
export const LockIcon = () => <svg {...common}><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>;
export const GlobeIcon = () => <svg {...common}><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/></svg>;
export const CheckIcon = () => <svg {...common}><path d="m5 12 4 4L19 6"/></svg>;
