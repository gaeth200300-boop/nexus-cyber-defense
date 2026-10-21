/* NEXUS API client: JWT refresh, structured errors and typed helpers. */

export const API_BASE = (import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_BASE || "/api/v1").replace(/\/$/, "");
export const AUTH_EVENT = "nexus:auth";

const ACCESS_KEY = "nexus_token";
const REFRESH_KEY = "nexus_refresh";

export type QueryValue = string | number | boolean | null | undefined;
export type Query = Record<string, QueryValue | QueryValue[]>;

export interface ApiOptions extends Omit<RequestInit, "body"> {
  /** JSON-serialisable request body. */
  body?: unknown;
  /** FormData, Blob, URLSearchParams or a pre-serialised string. */
  rawBody?: BodyInit | null;
  query?: Query;
  auth?: boolean;
  /** Internal: prevents infinite refresh loops. */
  retried?: boolean;
}

export interface ApiErrorDetail {
  code?: string;
  message?: string;
  hint?: string;
  suggestions?: unknown[];
  field?: string;
  [key: string]: unknown;
}

export class ApiError extends Error {
  status: number;
  code: string;
  detail: ApiErrorDetail;
  fields: { field: string; message: string }[];

  constructor(status: number, payload: unknown, fallback = `Request failed (HTTP ${status}).`) {
    const body = (payload && typeof payload === "object" ? payload : {}) as Record<string, unknown>;
    const rawDetail = body.detail;
    let detail: ApiErrorDetail = {};
    let validationMessage = "";
    if (rawDetail && typeof rawDetail === "object" && !Array.isArray(rawDetail)) {
      detail = rawDetail as ApiErrorDetail;
    } else if (Array.isArray(rawDetail)) {
      const first = rawDetail[0] as Record<string, unknown> | undefined;
      const loc = Array.isArray(first?.loc) ? first.loc.filter((part) => part !== "body").join(".") : "";
      validationMessage = `${loc ? `${loc}: ` : ""}${String(first?.msg || "Validation failed.")}`;
      detail = {
        code: "validation_error",
        message: validationMessage,
        errors: rawDetail
      };
    } else if (typeof rawDetail === "string") {
      detail = { code: body.code as string | undefined, message: rawDetail };
    }
    const message = String(
      detail.message || validationMessage || body.message || fallback
    );
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = String(detail.code || body.code || `http_${status}`);
    this.detail = detail;
    this.fields = Array.isArray(detail.errors)
      ? (detail.errors as Record<string, unknown>[])
          .map((entry) => ({
            field: Array.isArray(entry.loc)
              ? entry.loc.filter((part) => part !== "body").join(".")
              : String(entry.field || ""),
            message: String(entry.msg || entry.message || "")
          }))
          .filter((entry) => entry.message)
      : [];
  }
}

export function getAccessToken(): string | null {
  return localStorage.getItem(ACCESS_KEY);
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_KEY);
}

export function saveTokens(tokens: { access_token?: string; refresh_token?: string } | string, refresh?: string) {
  if (typeof tokens === "string") {
    localStorage.setItem(ACCESS_KEY, tokens);
    if (refresh) localStorage.setItem(REFRESH_KEY, refresh);
    return;
  }
  if (tokens.access_token) localStorage.setItem(ACCESS_KEY, tokens.access_token);
  if (tokens.refresh_token) localStorage.setItem(REFRESH_KEY, tokens.refresh_token);
}

export function clearTokens() {
  localStorage.removeItem(ACCESS_KEY);
  localStorage.removeItem(REFRESH_KEY);
}

export function notifyAuthChanged() {
  window.dispatchEvent(new Event(AUTH_EVENT));
}

export function errorMessage(error: unknown, fallback = "Something went wrong. Please try again."): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message || fallback;
  if (typeof error === "string" && error) return error;
  return fallback;
}

function buildQuery(query?: Query): string {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value)) {
      for (const entry of value) {
        if (entry !== undefined && entry !== null && entry !== "") params.append(key, String(entry));
      }
    } else {
      params.append(key, String(value));
    }
  }
  const serialised = params.toString();
  return serialised ? `?${serialised}` : "";
}

export interface RawResult<T> {
  data: T;
  response: Response;
}

async function parseResponse(response: Response): Promise<unknown> {
  if (response.status === 204 || response.status === 205) return null;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json") || contentType.includes("+json")) {
    try {
      return await response.json();
    } catch {
      return null;
    }
  }
  return response.text();
}

interface RequestOptions extends ApiOptions {
  expectResponse?: boolean;
}

let refreshPromise: Promise<boolean> | null = null;

async function refreshSession(): Promise<boolean> {
  if (refreshPromise) return refreshPromise;
  refreshPromise = (async () => {
    const refreshToken = getRefreshToken();
    if (!refreshToken) return false;
    try {
      const response = await fetch(`${API_BASE}/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ refresh_token: refreshToken })
      });
      if (!response.ok) {
        clearTokens();
        notifyAuthChanged();
        return false;
      }
      const data = (await response.json()) as { access_token: string; refresh_token: string };
      saveTokens(data);
      return true;
    } catch {
      return false;
    }
  })().finally(() => {
    refreshPromise = null;
  });
  return refreshPromise;
}

async function rawFetch(path: string, options: RequestOptions = {}, retried = false): Promise<Response> {
  const { body, rawBody, query, auth = true, headers: givenHeaders, retried: _ignored, expectResponse: _expect, ...init } = options;
  const headers = new Headers(givenHeaders);
  headers.set("Accept", headers.get("Accept") || "application/json");
  if (auth) {
    const token = getAccessToken();
    if (token) headers.set("Authorization", `Bearer ${token}`);
  }

  let payload: BodyInit | null | undefined = rawBody;
  if (body !== undefined && rawBody === undefined) {
    headers.set("Content-Type", "application/json");
    payload = JSON.stringify(body);
  }

  const url = `${API_BASE}${path.startsWith("/") ? path : `/${path}`}${buildQuery(query)}`;
  let response: Response;
  try {
    response = await fetch(url, { ...init, headers, body: payload });
  } catch (error) {
    throw new ApiError(0, {
      detail: {
        code: "network_error",
        message:
          error instanceof Error && error.message
            ? `Cannot reach the NEXUS API. ${error.message}`
            : "Cannot reach the NEXUS API. Check that the backend is running."
      }
    });
  }

  if (response.status === 401 && auth && !retried) {
    const refreshable = !path.startsWith("/auth/login") && !path.startsWith("/auth/bootstrap") && !path.startsWith("/auth/refresh");
    if (refreshable && getRefreshToken()) {
      const refreshed = await refreshSession();
      if (refreshed) return rawFetch(path, options, true);
    }
    clearTokens();
    notifyAuthChanged();
  }

  if (!response.ok) {
    const errorBody = await parseResponse(response);
    throw new ApiError(response.status, errorBody);
  }
  return response;
}

export async function apiFetch<T = unknown>(path: string, options: ApiOptions = {}): Promise<T> {
  const response = await rawFetch(path, options);
  return (await parseResponse(response)) as T;
}

/** Fetch with the response metadata; useful for pagination headers if ever added. */
export async function apiFetchRaw<T = unknown>(path: string, options: ApiOptions = {}): Promise<RawResult<T>> {
  const response = await rawFetch(path, options);
  return { data: (await parseResponse(response)) as T, response };
}

/** Authenticated file download. Report `download_url` values are API-relative. */
export async function downloadApiFile(path: string, filename?: string): Promise<void> {
  const normalised = path.startsWith("/api/") ? path.replace(/^\/api\/v\d+/, "") : path;
  const response = await rawFetch(normalised.startsWith("/") ? normalised : `/${normalised}`, {
    headers: { Accept: "*/*" }
  });
  const blob = await response.blob();
  const disposition = response.headers.get("content-disposition") || "";
  const match = disposition.match(/filename\*?=(?:UTF-8''|")?([^\";]+)/i);
  const suggested = match ? decodeURIComponent(match[1].replace(/"/g, "")) : "";
  const name = filename || suggested || "nexus-download";
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = name;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 10_000);
}

export function apiUrl(path: string): string {
  return `${API_BASE}${path.startsWith("/") ? path : `/${path}`}`;
}
