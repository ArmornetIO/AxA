// Personal access tokens — long-lived bearer credentials a user mints for
// themselves, to call the API from a script or an agent where a browser cookie
// cannot go.
//
// These return fallbacks instead of throwing, because every call site here is a
// screen that must still render: a failed list is an empty table, and a failed
// create is caught by the `token` field being empty. A host that wants the
// server's reason shown reads it from the transport's onFailure hook — see
// README, "What the host still owns".

import { send } from "./transport";

// `prefix` is the leading, non-secret slice of the token, kept so a user can
// tell two of their tokens apart in a list. The token itself is returned once,
// at creation, and never again.
export type PersonalAccessToken = {
  id: string;
  user_id: string;
  org_id: string;
  name: string;
  prefix: string;
  scopes: string[];
  created_at: string;
  expires_at?: string;
  last_used_at?: string;
  revoked_at?: string;
};

export type CreatePATInput = {
  name: string;
  scopes?: string[];
  expires_at?: string;
};

export type CreatePATResponse = {
  token: string;
  metadata: PersonalAccessToken;
};

const emptyPATResponse = (): CreatePATResponse => ({
  token: "",
  metadata: {
    id: "",
    user_id: "",
    org_id: "",
    name: "",
    prefix: "",
    scopes: [],
    created_at: "",
  },
});

export async function listPATs(
  includeRevoked = false,
): Promise<PersonalAccessToken[]> {
  const r = await send<PersonalAccessToken[]>(
    "GET",
    `/api/tokens${includeRevoked ? "?include_revoked=true" : ""}`,
    { credentials: true },
  );
  return r.ok ? (r.data ?? []) : [];
}

// The plaintext token is in this response and nowhere else, ever again. A caller
// that drops it has cost the user the credential.
export async function createPAT(
  input: CreatePATInput,
): Promise<CreatePATResponse> {
  const r = await send<CreatePATResponse>("POST", "/api/tokens", {
    body: input,
    credentials: true,
  });
  return r.ok ? r.data : emptyPATResponse();
}

export async function revokePAT(id: string): Promise<boolean> {
  const r = await send<unknown>(
    "DELETE",
    `/api/tokens/${encodeURIComponent(id)}`,
    { credentials: true },
  );
  return r.ok;
}

// listGrantableScopes returns the scopes the current user's org role is allowed
// to grant to a new token. The server derives this from the caller's role and
// enforces the same rule on create; a UI uses this only to avoid offering
// scopes that would be refused.
export async function listGrantableScopes(): Promise<string[]> {
  const r = await send<{ scopes?: string[] }>("GET", "/api/tokens/scopes", {
    credentials: true,
  });
  return r.ok ? (r.data?.scopes ?? []) : [];
}
