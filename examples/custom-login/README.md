# custom-login

A designed sign-in experience on top of identity's browser client
([`identity/ts`](../../ts)): type a workspace, pick an identity provider, land
signed in. Every server call comes from `identity`; what is here is the part a
product owns — the components and the look.

| File | What it is |
|---|---|
| `src/main.ts` | the flow: workspace → connector → redirect → callback → session |
| `src/components/WorkspaceStep.ts` | workspace form, prefilled from this browser's last sign-in |
| `src/components/ConnectorPicker.ts` | one button per provider; skipped when there is only one |
| `src/components/SessionCard.ts` | who you are, a protected API call, sign-out |
| `src/style.css` | the look |
| `vite.config.js` | the `identity` alias and a proxy to the backend |

No framework: components are functions that return an element, data in and
callbacks out. The same functions port to Svelte or React one-for-one.

## Run it

The backend is the [gin-basic](../gin-basic) example, run behind this dev
server so the browser sees one origin for the page, the API, the issuer and the
callback:

```sh
cd ../gin-basic && docker compose up -d
BASE_URL=http://localhost:5174 ADDR=:8081 go run .

# in another terminal
cd ../custom-login && npm install && npm run dev
```

Open http://localhost:5174 and sign in to the `demo` workspace.

## How it consumes identity

`identity/ts` is aliased as raw source, not installed — see its README. The
alias lives in `vite.config.js` (bundling) and `tsconfig.json` (types).
`identity` exports `setIdentityBaseUrl` for a page served from a different
origin than the API, and `setCSRFHeader` if your server names its CSRF header
differently.
