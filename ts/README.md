# identity/ts — TypeScript client for the identity service

The browser-side client for the endpoints this Go module serves: session and
sign-in flows, org connectors, invites, and personal access tokens.

It lives inside a Go module on purpose. Go ignores directories with no `.go`
files, so `ts/` costs the module nothing, and the alternative — a client in some
host app's `src/lib` — is how the client and the server it talks to drift apart.
Ship them together, version them together.

## The one hard rule: no `$lib`, no `$app/*`, no framework imports

A host consumes this by **aliasing raw source**, not by installing a built
package. The alias points at this directory and the host's own bundler compiles
the files as if they were its own:

```js
// svelte.config.js
alias: {
  identity: path.resolve(__dirname, '../identity/ts'),
  'identity/*': path.resolve(__dirname, '../identity/ts/*')
}
```

```ts
import { getSession, listInvites } from 'identity';
```

Because the source is compiled by the host, every import in these files must
resolve in the host's build. `$lib` and `$app/navigation` are SvelteKit aliases
that exist only inside a SvelteKit project's own `src/` — an import of either
from here resolves to the wrong place or to nothing at all, and a non-SvelteKit
consumer (a browser extension, a plain Vite app, a Node script) cannot resolve
them under any configuration.

So: **plain TypeScript, relative imports only.** No Svelte, no SvelteKit, no
component library, no generated route table. Types the clients need are defined
here rather than imported across the boundary, for the same reason.

## Modules

| File | What it covers |
|---|---|
| `transport.ts` | `fetch` wrapper, base URL, CSRF header, injection hooks |
| `session.ts` | `/api/auth/*` — session read, authorize, signup, callback, logout, memberships, org/invite lookup |
| `returnTo.ts` | the post-sign-in destination across the IdP round trip, same-origin only |
| `seenBefore.ts` | what this browser already told us (signed in before, last workspace) — never authority |
| `connectors.ts` | org connector CRUD + connection test |
| `invites.ts` | invite create/list/revoke, plus `inviteStatus` / `inviteLink` |
| `tokens.ts` | personal access tokens |
| `index.ts` | barrel re-export |

## Configuration

All of it is optional, and all of it is set once at host boot.

```ts
import { setIdentityBaseUrl, setCSRFHeader, setTransportHooks } from 'identity';

// Empty (the default) = same-origin. Set this only for a cross-origin consumer.
setIdentityBaseUrl('https://app.example.com');

// The name your server's CSRF guard checks. Defaults to 'x-armornet-csrf'.
setCSRFHeader('x-example-csrf');

setTransportHooks({
  beforeRequest: (ctx) => { /* dev latency hold, tracing, … */ },
  onFailure: (ctx, f) => { if (f.code === 'legal_acceptance_required') goto(ROUTES.onboarding); }
});
```

The hooks are the seam for cross-cutting **policy** — a redirect on a global
refusal code, a log line, a dev-only delay. They are deliberately not a place to
render per-call UI: every call funnels through them, and the call sites disagree
about how failure should be shown (connectors and invites throw so an admin
screen can render the reason; session and tokens fall back so a sign-in screen
still renders). A hook that raised a toast would raise it for all of them.

## Product data on the session

`Session` carries identity facts only. A product's own per-session payload is
additive JSON the server already returns, so a host declares an interface
extending `Session` and passes it as the type argument:

```ts
interface AppSession extends Session {
  agent_limits?: AgentLimits;
  quota?: QuotaSnapshot;
}
const s = await getSession<AppSession>();
```

The response is passed through untouched, so the extra fields arrive and stay
fully typed at the host's call sites — without identity having to know what an
agent limit is.

## What is deliberately NOT here

- **UI.** No components, no screens, no stores. The sign-in page, the invite
  table, the token drawer all stay in the host. This is a client, not a product.
- **Host product clients.** Anything whose types are the product's rather than
  identity's — Armornet's agents, risks, vendors, findings, and its legal
  acceptance flow.
- **Org administration beyond connectors.** Org rename and the email-domain
  allowlist are the host's admin surface today; they stay with it until they are
  shown to be identity's.
- **A build step.** No `package.json`, no `dist/`, no publish. The host compiles
  the source. If this ever ships to npm, that is a build added around these
  files, not a change to them.
