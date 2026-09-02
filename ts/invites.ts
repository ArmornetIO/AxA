// Org invites — create, list and revoke the invitations that let someone join
// an organization.
//
// These live only under /api/admin/orgs/:org_id/invites, which is gated by an
// org-match check: there is deliberately NO superadmin variant, so an operator
// browsing another org cannot mint invites into it. Callers must scope this to
// the caller's OWN org.
//
// The status and link helpers below travel with the client on purpose: both
// restate rules the server enforces at redemption time, and a host that
// reimplemented them locally would be free to drift out of agreement with the
// server about which invites are still usable.

import { send } from "./transport";

// Invite as the list endpoint returns it.
//
// NOTE: `token` is the live secret that redeems the invite, and the list
// endpoint returns it for every invite. That is what makes "copy invite link"
// possible after the fact, but it also means anything rendering this must treat
// the field as a credential — never log it, never put it in a URL bar.
export type Invite = {
  id: string;
  org_id: string;
  /** 'user' binds one email; 'domain' admits anyone with that email domain. */
  kind: "user" | "domain";
  /** Email for user-kind, domain suffix for domain-kind. Lowercased server-side. */
  binding: string;
  role: string;
  token: string;
  invited_by: string;
  target_user_id: string;
  accepted_by: string;
  accepted_at?: string | null;
  revoked_at?: string | null;
  expires_at: string;
  created_at: string;
};

export type InviteKind = "user" | "domain";
export type InviteRole = "admin" | "member";

// InviteStatus is the single state an invite is in, resolved in precedence
// order: an invite that was revoked AND expired reads as revoked, because that
// is the fact that explains it.
export type InviteStatus = "revoked" | "accepted" | "expired" | "pending";

export function inviteStatus(
  inv: Invite,
  now: number = Date.now(),
): InviteStatus {
  if (inv.revoked_at) return "revoked";
  // Only user-kind invites are consumed by acceptance. A domain invite stays
  // open for everyone on that domain until it expires or is revoked, which is
  // the same rule the server applies when it validates a redemption.
  if (inv.kind === "user" && inv.accepted_at) return "accepted";
  const exp = Date.parse(inv.expires_at);
  if (!Number.isNaN(exp) && exp <= now) return "expired";
  return "pending";
}

/** The link an invitee opens to redeem. Built from the caller's own origin.
 *
 *  `path` is the host's redemption ROUTE, not an identity endpoint — a host
 *  that mounts its invite screen elsewhere passes its own. */
export function inviteLink(
  token: string,
  origin?: string,
  path = "/invite",
): string {
  const base =
    origin ?? (typeof window !== "undefined" ? window.location.origin : "");
  return `${base}${path}/${token}`;
}

export async function listInvites(orgID: string): Promise<Invite[]> {
  const r = await send<Invite[]>(
    "GET",
    `/api/admin/orgs/${encodeURIComponent(orgID)}/invites`,
    { credentials: true },
  );
  if (!r.ok) throw new Error(r.error || `${r.status}`);
  return r.data ?? [];
}

export async function createInvite(
  orgID: string,
  kind: InviteKind,
  binding: string,
  role: InviteRole,
): Promise<Invite> {
  const r = await send<Invite>(
    "POST",
    `/api/admin/orgs/${encodeURIComponent(orgID)}/invites`,
    { body: { kind, binding, role }, credentials: true },
  );
  if (!r.ok) throw new Error(r.error || `${r.status}`);
  return r.data;
}

export async function revokeInvite(
  orgID: string,
  inviteID: string,
): Promise<void> {
  const r = await send<unknown>(
    "DELETE",
    `/api/admin/orgs/${encodeURIComponent(orgID)}/invites/${encodeURIComponent(inviteID)}`,
    { credentials: true },
  );
  if (!r.ok) throw new Error(r.error || `${r.status}`);
}
