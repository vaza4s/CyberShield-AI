export const API_BASE_URL = (
  import.meta.env.VITE_API_URL || "https://cybershield-ai-ym04.onrender.com"
).replace(/\/$/, "");

async function parseResponse(response) {
  let data = null;
  try {
    data = await response.json();
  } catch {
    data = { detail: await response.text().catch(() => "") };
  }

  if (!response.ok) {
    const message = data?.detail || data?.message || `Request failed (${response.status})`;
    throw new Error(typeof message === "string" ? message : JSON.stringify(message));
  }
  return data;
}

const SESSION_KEY = "cybershield_session_id";

export function getSessionId() {
  let id = sessionStorage.getItem(SESSION_KEY);
  if (!id) {
    id = globalThis.crypto?.randomUUID?.() || `cs-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    sessionStorage.setItem(SESSION_KEY, id);
  }
  return id;
}

function sessionHeaders(extra = {}) {
  return { ...extra, "X-CyberShield-Session": getSessionId() };
}

export async function analyzeUrl(url) {
  const response = await fetch(`${API_BASE_URL}/analyze`, {
    method: "POST",
    headers: sessionHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify({ url })
  });
  return parseResponse(response);
}

export async function scanFile(file) {
  const body = new FormData();
  body.append("file", file);
  const response = await fetch(`${API_BASE_URL}/scan-file`, {
    method: "POST",
    headers: sessionHeaders(),
    body
  });
  return parseResponse(response);
}

export async function analyzeLogin(payload) {
  const response = await fetch(`${API_BASE_URL}/analyze-login`, {
    method: "POST",
    headers: sessionHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(payload)
  });
  return parseResponse(response);
}


export async function scanQr(file) {
  const body = new FormData();
  body.append("file", file);
  const response = await fetch(`${API_BASE_URL}/scan-qr`, {
    method: "POST",
    headers: sessionHeaders(),
    body
  });
  return parseResponse(response);
}

export async function analyzeEmail(payload) {
  const response = await fetch(`${API_BASE_URL}/analyze-email`, {
    method: "POST",
    headers: sessionHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(payload)
  });
  return parseResponse(response);
}

export async function getPublicStats() {
  const response = await fetch(`${API_BASE_URL}/stats`);
  return parseResponse(response);
}

export async function adminLogin(username, password) {
  const response = await fetch(`${API_BASE_URL}/admin/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });
  return parseResponse(response);
}

export async function adminGet(path, token) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return parseResponse(response);
}
