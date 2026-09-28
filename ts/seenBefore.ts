// ── Have we seen this browser before? ────────────────────────────────────────
// One small record of what a PERSON on this device has already told us, kept so
// the sign-in surfaces can stop asking them for it a second time: whether they
// have ever had a session here, and which workspace they used.
//
// `localStorage`, deliberately the opposite choice to `returnTo` next door. A
// return-to belongs to one sign-in attempt in one tab and must not outlive it;
// this is the standing fact that survives the session it was learned in, which
// is the only way it can be useful on the visit AFTER the cookie expired.
//
// Nothing here is authority. It decides whether to ASK the server a question —
// never what the answer is. A forged or stale record costs one wasted probe and
// a prefilled field; it cannot admit anybody.

const KEY = "armornet:seen";

export interface SeenBefore {
  /** This browser has held a session at some point. */
  signedIn?: boolean;
  /** The workspace slug last carried into a sign-in from this browser. */
  workspace?: string;
}

export function recallVisitor(): SeenBefore | null {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    // Anything can be in shared storage — another app on the origin, a hand
    // edit, an older shape of this record. A malformed one is no record.
    if (!parsed || typeof parsed !== "object") return null;
    const { signedIn, workspace } = parsed as SeenBefore;
    return {
      signedIn: signedIn === true,
      workspace: typeof workspace === "string" && workspace ? workspace : undefined,
    };
  } catch {
    return null;
  }
}

function write(patch: SeenBefore): void {
  try {
    localStorage.setItem(KEY, JSON.stringify({ ...recallVisitor(), ...patch }));
  } catch {
    // Storage can be unavailable (private mode, a blocked partition). Forgetting
    // costs the visitor one form; failing the sign-in would cost the session.
  }
}

/** Record that a session existed here. Called wherever one is proven, not where
 *  one is merely attempted. */
export function noteSignedIn(): void {
  write({ signedIn: true });
}

/** Remember the workspace a sign-in was actually started against — not every
 *  slug typed into the box, or a stranger probing names would overwrite it. */
export function noteWorkspace(workspace: string): void {
  write({ workspace });
}

/**
 * Drop the remembered workspace, keeping the rest.
 *
 * The escape hatch behind "use a different workspace": a member of two orgs, a
 * consultant, a renamed slug. Without it the shortcut becomes a trap — the one
 * failure mode that would make remembering worse than not.
 */
export function forgetWorkspace(): void {
  try {
    const rest = recallVisitor();
    if (!rest) return;
    delete rest.workspace;
    localStorage.setItem(KEY, JSON.stringify(rest));
  } catch {
    // See write().
  }
}
