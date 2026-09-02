// HTTP transport for the identity clients.
//
// This exists rather than reusing a host's shared fetch helper because a host's
// helper is entangled with its UI: a typical `send` imports a toast library,
// a router and a generated route table. None of that can cross into an
// aliased-source package (see README), and none of it is identity's business —
// so the transport here is plain `fetch` with two injection seams for the
// cross-cutting behaviour a host legitimately needs to keep.

/** Base URL prepended to every request. Empty = same-origin (a host app served
 *  by the identity backend). A cross-origin consumer — a browser extension on a
 *  chrome-extension:// page, a separate marketing origin — sets the backend
 *  origin here so the relative paths in the clients resolve. */
let baseUrl = "";

export function setIdentityBaseUrl(url: string): void {
  baseUrl = url ? url.replace(/\/+$/, "") : "";
}

export function getIdentityBaseUrl(): string {
  return baseUrl;
}

// The host's CSRF guard names this header; identity does not define one, since
// the guard is server-side and belongs to whoever mounts these routes. The
// default matches Armornet's `csrfRequired` middleware.
let csrfHeader = "x-armornet-csrf";

export function setCSRFHeader(name: string): void {
  csrfHeader = name;
}

export interface RequestContext {
  method: string;
  /** Path as written by the client, before `baseUrl` is prepended. */
  path: string;
}

export interface Failure {
  /** 0 for network errors, aborts and unparseable responses. */
  status: number;
  /** The server's `{"error": "…"}` message, or '' when there was none. */
  error: string;
  /** The server's machine-readable marker where it sets one. Branch on this
   *  rather than on `error`, which is prose, or on `status`, which is ambiguous. */
  code?: string;
}

/**
 * Cross-cutting behaviour a host injects once at boot.
 *
 * These are for POLICY and observability — a redirect on a global refusal code,
 * a latency hold in development, a log line. They deliberately are not a place
 * to render per-call UI: every identity call funnels through here, and the call
 * sites differ in how they want failures shown (some throw, some fall back), so
 * a hook that raised a toast would raise it for all of them.
 */
export interface TransportHooks {
  beforeRequest?(ctx: RequestContext): void | Promise<void>;
  onFailure?(ctx: RequestContext, failure: Failure): void;
}

let hooks: TransportHooks = {};

export function setTransportHooks(next: TransportHooks): void {
  hooks = next ?? {};
}

export type ApiResult<T> =
  | { ok: true; status: number; data: T }
  | { ok: false; status: number; error: string; code?: string };

export interface SendOpts {
  body?: unknown;
  signal?: AbortSignal;
  /** Send cookies and, on mutations, the CSRF header the server's guard
   *  requires. Off by default so a bearer-authed caller does not leak cookies. */
  credentials?: boolean;
}

// send performs one request and reports the outcome instead of throwing, so
// each client can choose its own failure shape. A 204 resolves with `undefined`
// as the payload — callers that expect a body treat that as the empty case.
export async function send<T>(
  method: string,
  path: string,
  opts: SendOpts = {},
): Promise<ApiResult<T>> {
  const { body, signal, credentials } = opts;
  const ctx: RequestContext = { method, path };
  try {
    await hooks.beforeRequest?.(ctx);
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (credentials && method !== "GET") headers[csrfHeader] = "1";
    const res = await fetch(`${baseUrl}${path}`, {
      method,
      signal,
      credentials: credentials ? "include" : undefined,
      headers: Object.keys(headers).length ? headers : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      let error = "";
      let code: string | undefined;
      try {
        const b = (await res.clone().json()) as {
          error?: string;
          code?: string;
        };
        error = b?.error ?? "";
        code = b?.code;
      } catch {
        /* not JSON — leave error empty, caller supplies a human fallback */
      }
      const failure: Failure = { status: res.status, error, code };
      hooks.onFailure?.(ctx, failure);
      return { ok: false, ...failure };
    }
    if (res.status === 204) return { ok: true, status: 204, data: undefined as T };
    return { ok: true, status: res.status, data: (await res.json()) as T };
  } catch (err) {
    // An abort is the caller's own doing, so it is reported as a failure but
    // never handed to onFailure — a host that logs or redirects there would fire
    // on every superseded request.
    if (err instanceof DOMException && err.name === "AbortError") {
      return { ok: false, status: 0, error: "" };
    }
    const failure: Failure = { status: 0, error: "" };
    hooks.onFailure?.(ctx, failure);
    return { ok: false, ...failure };
  }
}

// failureMessage picks the sentence to show a human: the server's own
// explanation when it gave one, since it names the actual cause, and otherwise
// the caller's fallback. Status 0 is separated out because "Failed to load X"
// is misleading when nothing ever reached the server.
export function failureMessage(
  r: { status: number; error: string },
  fallback: string,
  networkFallback = "Network error.",
): string {
  return r.error || (r.status === 0 ? networkFallback : fallback);
}
