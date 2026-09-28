// ── Where the caller was trying to go ────────────────────────────────────────
// A gated page redirects an unauthenticated visitor to sign-in, and the
// destination has to survive the round trip — including the hop out to the
// identity provider and back through the callback.
//
// It cannot ride the URL the whole way: the OAuth leg is redirected by the IdP,
// which knows nothing about our query parameters. So it is stashed before we
// leave and consumed when we land.
//
// `sessionStorage`, not `localStorage`: a destination is a property of THIS
// sign-in attempt in THIS tab. A stale one in shared storage would silently
// hijack an unrelated login in another tab days later.

const KEY = "armornet:return-to";

/**
 * Is this somewhere we are willing to send a browser after sign-in?
 *
 * Only same-origin paths. This value arrives in a query parameter, which means
 * anybody can put anything in it — an unvalidated return-to is an open redirect
 * with a helpful name, and the classic phishing shape is a real login page that
 * hands you to an attacker's site afterwards.
 *
 * Rejected, in order: anything not starting with `/`, protocol-relative `//host`
 * (a URL, not a path), anything carrying a scheme, and backslashes (some
 * browsers normalise `\` to `/`, so `/\evil.com` can become protocol-relative).
 */
export function isLocalPath(dest: string | null | undefined): dest is string {
  if (!dest || dest[0] !== "/") return false;
  if (dest.startsWith("//")) return false;
  if (dest.includes("\\")) return false;
  if (dest.includes("://")) return false;
  if (isSignInPath(dest)) return false;
  return true;
}

/**
 * Pages that are the sign-in flow itself, and so can never be a destination.
 *
 * The callback is the one that bites: it is only meaningful with the `code` the
 * identity provider put in its query, that code is single-use, and the page
 * strips it from the URL on arrival. Sending someone back there hands them a
 * callback with nothing to exchange, which surfaces as "Unable to authenticate"
 * on a sign-in that had in fact already succeeded. Login and signup are the
 * same shape one step earlier — returning to them after signing in is a loop.
 */
let signInPaths = new Set(["/login", "/signup", "/callback"]);

/** For a host whose sign-in pages live somewhere other than the defaults. */
export function setSignInPaths(paths: string[]): void {
  signInPaths = new Set(paths);
}

function isSignInPath(dest: string): boolean {
  const path = dest.split(/[?#]/, 1)[0];
  return signInPaths.has(path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path);
}

/** Remember where to go, if the destination is one we will honour. */
export function rememberReturnTo(dest: string | null | undefined): void {
  if (!isLocalPath(dest)) return;
  try {
    sessionStorage.setItem(KEY, dest);
  } catch {
    // Storage can be unavailable (private mode, a blocked partition). Losing
    // the destination costs the visitor one navigation; failing the sign-in
    // would cost them the session.
  }
}

/**
 * Take the destination, if there is one. Reading CONSUMES it — a return-to that
 * survives its own use will fire again on the next sign-in.
 */
export function takeReturnTo(): string | null {
  try {
    const dest = sessionStorage.getItem(KEY);
    sessionStorage.removeItem(KEY);
    return isLocalPath(dest) ? dest : null;
  } catch {
    return null;
  }
}

/** The query key a server-side sign-in redirect uses. Armornet's must match
 *  `returnParam` in server/ui/serve.go. */
export const RETURN_PARAM = "next";
