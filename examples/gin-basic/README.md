# gin-basic

A Gin API behind AxA's browser sign-in, in one process:

- the issuer (embedded Dex) at `/dex`,
- the sign-in flow (`axa/web`) at `/api/auth/*`,
- your API at `/api/*`, refused without a live session cookie.

Dex's mock connector stands in for a real identity provider, so nothing but
Postgres is needed.

```sh
docker compose up -d          # Postgres on :5433
go run .                      # http://localhost:8081
```

Open http://localhost:8081, press **Sign in**, then **GET /api/hello**.

## What to read

- `main.go` — the whole wiring. `mountAuth` is the three lines that put
  axa/web's `net/http` routes on a Gin router; `requireSession` is all
  "behind our auth" means for the API.
- `index.html` — the browser half of the round trip, with no build step. The
  [custom-login](../custom-login) example does the same with a designed UI.

## Things the example does that a real app should know about

- **Schema is yours.** AxA never migrates. `pgstore.Schema()` and
  `dex.Schema()` return idempotent DDL; this example runs them at start, a real
  app folds them into its migrations.
- **A public client, no secret.** The browser flow proves itself with PKCE, so
  the OAuth client is registered `Public` and there is no secret to keep.
- **`__Host-` cookies are `Secure`.** Browsers treat `http://localhost` as
  secure, so this works locally; anywhere else, serve HTTPS.
- **Single tenant.** `SelfRegister` makes a first sign-in a member of the one
  org. Leave it off in a product with more than one.

| Variable | Default |
|---|---|
| `DATABASE_URL` | `postgres://postgres:identity@localhost:5433/identity?sslmode=disable` |
| `BASE_URL` | `http://localhost:8081` — the origin the browser sees |
| `ADDR` | `BASE_URL`'s port — set it when a proxy owns `BASE_URL` |

Outside this repo, delete the `replace` block in `go.mod` and require a tagged
AxA release.
