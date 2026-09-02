// Entry point for the identity TypeScript client.
//
// A host may import this barrel or the individual modules — the alias resolves
// raw source and the host's own bundler tree-shakes either way.

export {
  setIdentityBaseUrl,
  getIdentityBaseUrl,
  setCSRFHeader,
  setTransportHooks,
  send,
  failureMessage,
} from "./transport";
export type {
  ApiResult,
  SendOpts,
  Failure,
  RequestContext,
  TransportHooks,
} from "./transport";

export {
  setAuthBaseUrl,
  getAuthBaseUrl,
  resolveSlug,
  getSession,
  listMyOrgs,
  authorize,
  signup,
  callback,
  getInvite,
  inviteAuthorize,
  logout,
} from "./session";
export type {
  Session,
  MyOrg,
  ConnectorInfo,
  OrgConnectors,
  AuthorizeResult,
  InviteDetail,
} from "./session";

export {
  isLocalPath,
  setSignInPaths,
  rememberReturnTo,
  takeReturnTo,
  RETURN_PARAM,
} from "./returnTo";

export {
  recallVisitor,
  noteSignedIn,
  noteWorkspace,
  forgetWorkspace,
} from "./seenBefore";
export type { SeenBefore } from "./seenBefore";

export {
  getOrg,
  listConnectors,
  createConnector,
  deleteConnector,
  testConnector,
} from "./connectors";
export type { OrgConnector, OrgInfo } from "./connectors";

export {
  inviteStatus,
  inviteLink,
  listInvites,
  createInvite,
  revokeInvite,
} from "./invites";
export type { Invite, InviteKind, InviteRole, InviteStatus } from "./invites";

export {
  listPATs,
  createPAT,
  revokePAT,
  listGrantableScopes,
} from "./tokens";
export type {
  PersonalAccessToken,
  CreatePATInput,
  CreatePATResponse,
} from "./tokens";
