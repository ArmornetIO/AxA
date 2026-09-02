// Session and sign-in flows against /api/auth/* and the org/connector + invite
// lookups that drive them.
//
// This is the core of the identity client: everything a host needs to discover
// which upstream connectors an org offers, bounce the browser through one, and
// read back who the resulting cookie says the caller is.
//
// It is a client for the identity service's own endpoints, so it belongs beside
// the server that answers them, not inside any one host app.

import { send, failureMessage } from "./transport";

// Base-URL setters keep their historical names alongside the transport's, so a
// consumer that already calls setAuthBaseUrl() (the KAE browser panel) needs no
// change. Same module-level variable underneath.
export {
  setIdentityBaseUrl as setAuthBaseUrl,
  getIdentityBaseUrl as getAuthBaseUrl,
} from "./transport";

/**
 * Who the current cookie says the caller is.
 *
 * Deliberately only the identity facts. A product's own per-session payload —
 * entitlements, quotas, feature state — is additive JSON the server already
 * returns, so a host declares an interface extending this one and passes it to
 * getSession()/callback() as the type argument. That keeps product types fully
 * typed at the host's call sites without identity having to know them, and
 * costs nothing at runtime: the response is passed through untouched.
 *
 *   interface AppSession extends Session { entitlements?: Entitlements }
 *   const s = await getSession<AppSession>();
 */
export interface Session {
  subject: string;
  /** The connector that signed this session in, so a re-authorization needs no
   *  picker. Empty on sessions older than the field. */
  connector_id?: string;
  org_id?: string;
  /** Human-readable org name, for a host to render in chrome without a second call. */
  org_name?: string;
  authenticated: boolean;
  first_login?: boolean;
  org_role?: string;
}

export interface ConnectorInfo {
  id: string;
  type: string;
  name: string;
}

export interface OrgConnectors {
  org_id: string;
  connectors: ConnectorInfo[];
}

export interface AuthorizeResult {
  redirect_url: string;
}

export interface InviteDetail {
  id: string;
  org_id: string;
  org_slug: string;
  kind: "user" | "domain";
  role: "admin" | "member";
  expires_at: string;
  valid: boolean;
}

// The sign-in screens render these strings directly, so they are sentences
// rather than status codes: a 404 here means the workspace URL was mistyped,
// which is a thing the person can fix, and saying so is the whole point.
export async function resolveSlug(
  slug: string,
): Promise<{ ok: boolean; data?: OrgConnectors; error?: string }> {
  const r = await send<OrgConnectors>(
    "GET",
    `/api/orgs/${encodeURIComponent(slug)}/connectors`,
    { credentials: true },
  );
  if (!r.ok) {
    if (r.status === 404) {
      return {
        ok: false,
        error:
          "Organization not found. Check your workspace URL and try again.",
      };
    }
    return {
      ok: false,
      error: r.status === 0 ? "Network error." : "Could not reach server.",
    };
  }
  return { ok: true, data: r.data };
}

// null means "not signed in" and also "could not tell" — a caller that cannot
// reach the server has no session either way, and the sign-in screens treat
// both the same.
export async function getSession<S extends Session = Session>(): Promise<S | null> {
  const r = await send<S>("GET", "/api/auth/session", { credentials: true });
  return r.ok ? r.data : null;
}

export interface MyOrg {
  org_id: string;
  role: string;
  name?: string;
  slug?: string;
  /** The org's own profile; absent until it has one. */
  logo?: string;
  website?: string;
  description?: string;
  /** Whether the org is admitted to the alpha. Absent when the server could
   *  not say, which reads as unknown, never as either answer. */
  admitted?: boolean;
}

/** The caller's memberships — works for a session that names no org. */
export async function listMyOrgs(): Promise<{ orgs: MyOrg[]; activeOrgId: string } | null> {
  const r = await send<{ orgs?: MyOrg[]; active_org_id?: string }>("GET", "/api/auth/orgs", {
    credentials: true,
  });
  if (!r.ok) return null;
  return { orgs: r.data.orgs ?? [], activeOrgId: r.data.active_org_id ?? "" };
}

// `intent` names what the sign-in is for, carried out by the callback while the
// verified email is still in memory. The server holds the allowlist; a value it
// does not know is refused, so a host types its own union over this string.
export async function authorize(
  orgId: string,
  connectorId: string,
  intent?: string,
): Promise<{ ok: boolean; redirectUrl?: string; error?: string }> {
  const r = await send<AuthorizeResult>("POST", "/api/auth/authorize", {
    body: { org_id: orgId, connector_id: connectorId, intent },
    credentials: true,
  });
  if (!r.ok) {
    return { ok: false, error: failureMessage(r, "Authorization failed", "Network error") };
  }
  return { ok: true, redirectUrl: r.data.redirect_url };
}

/**
 * Start a signup against a GLOBAL connector.
 *
 * The sibling of `authorize`, minus the org: signing up has no workspace to
 * resolve a connector from yet, so the server picks from the global set.
 */
export async function signup(
  connectorId: string,
  intent?: string,
): Promise<{ ok: boolean; redirectUrl?: string; error?: string }> {
  const r = await send<AuthorizeResult>("POST", "/api/auth/signup", {
    body: { connector_id: connectorId, intent },
    credentials: true,
  });
  if (!r.ok) {
    return {
      ok: false,
      error: failureMessage(r, "Something went wrong. Please try again.", "Network error"),
    };
  }
  return { ok: true, redirectUrl: r.data.redirect_url };
}

export async function callback<S extends Session = Session>(
  code: string,
  state: string,
): Promise<{ ok: boolean; session?: S; stepUpReturnTo?: string; error?: string }> {
  const r = await send<S & { step_up?: boolean; return_to?: string }>(
    "POST",
    "/api/auth/callback",
    { body: { code, state }, credentials: true },
  );
  if (!r.ok) {
    return { ok: false, error: failureMessage(r, "Authentication failed", "Network error") };
  }
  // A step-up proved an upstream account for the session that already exists;
  // there is no new session to land with.
  if (r.data.step_up) return { ok: true, stepUpReturnTo: r.data.return_to };
  return { ok: true, session: r.data };
}

export async function getInvite(
  token: string,
): Promise<{ ok: boolean; data?: InviteDetail; error?: string }> {
  const r = await send<InviteDetail>(
    "GET",
    `/api/invites/${encodeURIComponent(token)}`,
    { credentials: true },
  );
  if (!r.ok) {
    if (r.status === 404) return { ok: false, error: "Invite not found." };
    return {
      ok: false,
      error: r.status === 0 ? "Network error." : "Could not reach server.",
    };
  }
  return { ok: true, data: r.data };
}

// The invite variant of authorize: the token stands in for the org, because an
// invitee has no workspace URL to type and may not know the org's slug at all.
export async function inviteAuthorize(
  inviteToken: string,
  connectorId: string,
): Promise<{ ok: boolean; redirectUrl?: string; error?: string }> {
  const r = await send<AuthorizeResult>("POST", "/api/auth/invite-authorize", {
    body: { invite_token: inviteToken, connector_id: connectorId },
    credentials: true,
  });
  if (!r.ok) {
    return { ok: false, error: failureMessage(r, "Authorization failed", "Network error") };
  }
  return { ok: true, redirectUrl: r.data.redirect_url };
}

// Failure is not reported: the caller's next move is to send the browser to the
// signed-out screen either way, and a session it could not clear is one the
// server will reject on the next request anyway.
export async function logout(): Promise<void> {
  await send<unknown>("POST", "/api/auth/logout", { credentials: true });
}
