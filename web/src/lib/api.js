const ACCESS_TOKEN_KEY = "pi_access_token";
const REFRESH_TOKEN_KEY = "pi_refresh_token";

export function getAccessToken() {
  return localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function getRefreshToken() {
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function setTokens({ accessToken, refreshToken }) {
  if (accessToken) {
    localStorage.setItem(ACCESS_TOKEN_KEY, accessToken);
  }
  if (refreshToken) {
    localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
  }
}

export function clearTokens() {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
}

async function refreshAccessToken() {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return null;

  const response = await fetch("/api/v1/auth/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refreshToken }),
  });

  if (!response.ok) {
    clearTokens();
    return null;
  }

  const data = await response.json();
  const tokens = data.tokens || {};
  setTokens({ accessToken: tokens.access_token, refreshToken: tokens.refresh_token });
  return tokens.access_token || null;
}

export async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const accessToken = getAccessToken();
  if (accessToken) {
    headers.set("Authorization", `Bearer ${accessToken}`);
  }
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(path, { ...options, headers });
  if (response.status !== 401) {
    return response;
  }

  const newAccessToken = await refreshAccessToken();
  if (!newAccessToken) {
    return response;
  }

  headers.set("Authorization", `Bearer ${newAccessToken}`);
  return fetch(path, { ...options, headers });
}

export async function fetchJson(path, options = {}) {
  const response = await apiFetch(path, options);
  const contentType = response.headers.get("content-type") || "";
  const isJson = contentType.includes("application/json");
  const payload = isJson ? await response.json() : null;
  if (!response.ok) {
    const error = new Error((payload && (payload.error || payload.detail)) || "Request failed");
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

export async function accessStatus() {
  return fetchJson("/api/access/status");
}

export async function verifyAccess(code) {
  return fetchJson("/api/access/verify", {
    method: "POST",
    body: JSON.stringify({ code }),
  });
}

export async function login(email, password) {
  const data = await fetchJson("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  const tokens = data.tokens || {};
  setTokens({ accessToken: tokens.access_token, refreshToken: tokens.refresh_token });
  return data.user;
}

export async function register(payload) {
  const data = await fetchJson("/api/v1/auth/register", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  const tokens = data.tokens || {};
  setTokens({ accessToken: tokens.access_token, refreshToken: tokens.refresh_token });
  return data.user;
}

export async function logout() {
  await apiFetch("/api/v1/auth/logout", { method: "POST" });
  clearTokens();
}

export async function fetchMe() {
  return fetchJson("/api/v1/auth/me");
}
