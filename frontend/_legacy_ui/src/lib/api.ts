// API client — thin wrapper over fetch with token refresh + error normalization.

const TOKEN_KEY = 'nexus_token';
const REFRESH_KEY = 'nexus_refresh';

export function getToken(): string | null { return localStorage.getItem(TOKEN_KEY); }
export function getRefresh(): string | null { return localStorage.getItem(REFRESH_KEY); }
export function setTokens(token: string, refresh: string) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(REFRESH_KEY, refresh);
}
export function clearTokens() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(REFRESH_KEY);
}

export class ApiError extends Error {
  status: number;
  code: string;
  fields?: { field: string; message: string }[];
  constructor(status: number, body: any) {
    // FastAPI wraps our api_error payload in `detail` ({code, message, ...}).
    // Validation errors use detail as an array instead, so normalize both.
    const detail = body?.detail;
    const payload = detail && typeof detail === 'object' && !Array.isArray(detail) ? detail : body;
    const validation = Array.isArray(detail) ? detail[0]?.msg : Array.isArray(body?.detail) ? body.detail[0]?.msg : null;
    super(payload?.message || validation || `HTTP ${status}`);
    this.status = status;
    this.code = payload?.code || `http_${status}`;
    this.fields = payload?.errors || body?.errors;
  }
}

let refreshing: Promise<string | null> | null = null;

async function rawFetch(path: string, init: RequestInit = {}, _retry = true): Promise<Response> {
  const headers: Record<string, string> = { ...(init.headers as any) };
  const token = getToken();
  if (token && !headers['X-API-Key']) headers['Authorization'] = `Bearer ${token}`;
  if (init.body && typeof init.body === 'string' && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(path, { ...init, headers });

  if (res.status === 401 && _retry && !path.includes('/auth/')) {
    // try refresh once
    const rt = getRefresh();
    if (rt) {
      refreshing = refreshing || (async () => {
        const r = await fetch('/api/v1/auth/refresh', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: rt }),
        });
        if (!r.ok) { clearTokens(); return null; }
        const data = await r.json();
        setTokens(data.access_token, data.refresh_token);
        return data.access_token as string;
      })();
      const newToken = await refreshing;
      refreshing = null;
      if (newToken) return rawFetch(path, init, false);
    }
    clearTokens();
    window.location.hash = '#/login';
    throw new ApiError(401, { message: 'Session expired' });
  }
  return res;
}

async function parseBody(res: Response) {
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) return res.json();
  if (res.status === 204) return null;
  return res.text();
}

export async function api<T = any>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await rawFetch(`/api/v1${path}`, init);
  if (!res.ok) {
    let body: any = null;
    try { body = await parseBody(res); } catch { /* ignore */ }
    throw new ApiError(res.status, body);
  }
  return parseBody(res) as Promise<T>;
}

export async function apiUpload<T = any>(path: string, file: File, extra: Record<string, string> = {}): Promise<T> {
  const fd = new FormData();
  fd.append('file', file);
  for (const [k, v] of Object.entries(extra)) fd.append(k, v);
  const res = await rawFetch(`/api/v1${path}`, { method: 'POST', body: fd });
  if (!res.ok) {
    let body: any = null;
    try { body = await res.json(); } catch { /* ignore */ }
    throw new ApiError(res.status, body);
  }
  return res.json();
}

export function downloadUrl(path: string): string {
  return `/api/v1${path}`;
}

export async function downloadFile(path: string, filename: string) {
  const res = await rawFetch(`/api/v1${path}`);
  if (!res.ok) throw new ApiError(res.status, { message: 'Download failed' });
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ---- SSE stream helper ----
export function openEventSource(path: string, onEvent: (data: any) => void, onError?: () => void): EventSource {
  // EventSource cannot set headers; token passed via query (backend supports it minimally)
  const token = getToken();
  const sep = path.includes('?') ? '&' : '?';
  const es = new EventSource(`/api/v1${path}${sep}access_token=${encodeURIComponent(token || '')}`);
  es.onmessage = (ev) => {
    try { onEvent(JSON.parse(ev.data)); } catch { /* ignore */ }
  };
  es.onerror = () => { onError?.(); };
  return es;
}
