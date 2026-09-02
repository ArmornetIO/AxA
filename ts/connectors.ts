// Org connector administration — the upstream identity providers an org's
// members sign in through.
//
// The read side of this is also public: session.ts's resolveSlug() lists an
// org's connectors to an anonymous visitor on the sign-in screen. These are the
// admin endpoints behind them, which carry the config and can mutate it.
//
// These throw on failure rather than returning a fallback: an admin screen that
// silently rendered an empty connector list would read as "this org has no way
// to sign in", which is a much louder claim than "the request failed".

import { send } from "./transport";

export type OrgConnector = {
  id: string;
  type: string;
  name: string;
};

export type OrgInfo = {
  id: string;
  name: string;
  slug: string;
};

// The exception to the throwing rule: an org header renders around whatever it
// has, so a missing name is a degraded header rather than a failed screen.
export async function getOrg(orgId: string): Promise<OrgInfo | null> {
  const r = await send<OrgInfo>(
    "GET",
    `/api/admin/orgs/${encodeURIComponent(orgId)}`,
    { credentials: true },
  );
  return r.ok ? r.data : null;
}

export async function listConnectors(orgId: string): Promise<OrgConnector[]> {
  const r = await send<{ connectors?: OrgConnector[] }>(
    "GET",
    `/api/admin/orgs/${encodeURIComponent(orgId)}/connectors`,
    { credentials: true },
  );
  if (!r.ok) throw new Error(r.error || `${r.status}`);
  return r.data.connectors ?? [];
}

// `config` is the upstream provider's own settings (client id/secret, issuer,
// …) and is write-only — the read endpoints never return it back.
export async function createConnector(
  orgId: string,
  type: string,
  name: string,
  config: Record<string, unknown>,
): Promise<{ id: string }> {
  const r = await send<{ id: string }>(
    "POST",
    `/api/admin/orgs/${encodeURIComponent(orgId)}/connectors`,
    { body: { type, name, config }, credentials: true },
  );
  if (!r.ok) throw new Error(r.error || `${r.status}`);
  return r.data;
}

export async function deleteConnector(
  orgId: string,
  connectorId: string,
): Promise<void> {
  const r = await send<unknown>(
    "DELETE",
    `/api/admin/orgs/${encodeURIComponent(orgId)}/connectors/${encodeURIComponent(connectorId)}`,
    { credentials: true },
  );
  if (!r.ok) throw new Error(r.error || `${r.status}`);
}

// Two failure grains, and they are not the same thing: a rejected request
// throws, while a completed test that found the connector misconfigured
// resolves with {ok:false}. Only the second one is about the connector.
export async function testConnector(
  orgId: string,
  connectorId: string,
): Promise<{ ok: boolean; error?: string }> {
  const r = await send<{ ok: boolean; error?: string }>(
    "POST",
    `/api/admin/orgs/${encodeURIComponent(orgId)}/connectors/${encodeURIComponent(connectorId)}/test`,
    { credentials: true },
  );
  if (!r.ok) throw new Error(r.error || `${r.status}`);
  return r.data;
}
