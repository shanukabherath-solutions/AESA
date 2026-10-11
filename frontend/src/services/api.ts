const TOKEN_KEY = "aesa.token";

export class ApiError extends Error {
  constructor(public status: number, public detail: unknown) {
    super(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  /** Human-readable message; the gate returns { message, reasons[] }. */
  get reasons(): string[] {
    const d = this.detail as { reasons?: string[] } | null;
    return d && typeof d === "object" && Array.isArray(d.reasons) ? d.reasons : [];
  }
  get headline(): string {
    const d = this.detail as { message?: string } | string | null;
    if (typeof d === "string") return d;
    return d && typeof d === "object" && d.message ? d.message : this.message;
  }
}

export const tokenStore = {
  get: () => sessionStorage.getItem(TOKEN_KEY),
  set: (t: string) => sessionStorage.setItem(TOKEN_KEY, t),
  clear: () => sessionStorage.removeItem(TOKEN_KEY),
};

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  const token = tokenStore.get();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(`/api${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (res.status === 401 && path !== "/auth/login") {
    tokenStore.clear();
    window.dispatchEvent(new Event("aesa:unauthorized"));
  }
  if (!res.ok) {
    let detail: unknown = res.statusText;
    try { detail = (await res.json()).detail ?? detail; } catch { /* non-JSON error body */ }
    throw new ApiError(res.status, detail);
  }
  return (await res.json()) as T;
}

export const api = {
  get: <T,>(p: string) => request<T>("GET", p),
  post: <T,>(p: string, b?: unknown) => request<T>("POST", p, b ?? {}),
  patch: <T,>(p: string, b: unknown) => request<T>("PATCH", p, b),
};

export function qs(params: Record<string, string | number | undefined>): string {
  const u = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== "") u.set(k, String(v)); });
  const s = u.toString();
  return s ? `?${s}` : "";
}
