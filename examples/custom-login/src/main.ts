// A custom sign-in experience over identity's browser client.
//
// Everything that talks to the server comes from `axa` (axa/ts): the
// workspace lookup, the redirect out, the callback, the session. What is left
// here is presentation — the part a product wants to own.
import {
  authorize,
  callback,
  forgetWorkspace,
  getSession,
  logout,
  noteSignedIn,
  noteWorkspace,
  recallVisitor,
  rememberReturnTo,
  resolveSlug,
  setSignInPaths,
  takeReturnTo,
  type ConnectorInfo,
} from "axa";
import { ConnectorPicker } from "./components/ConnectorPicker";
import { SessionCard } from "./components/SessionCard";
import { WorkspaceStep } from "./components/WorkspaceStep";

const app = document.getElementById("app")!;
const show = (el: HTMLElement) => app.replaceChildren(el);

// This app's sign-in pages, which a return-to may never point back at.
setSignInPaths(["/callback"]);

function askWorkspace(error?: string) {
  show(
    WorkspaceStep({
      remembered: recallVisitor()?.workspace,
      error,
      onSubmit: pickConnector,
      onForget: () => {
        forgetWorkspace();
        askWorkspace();
      },
    }),
  );
}

async function pickConnector(slug: string) {
  const r = await resolveSlug(slug);
  if (!r.ok || !r.data) return askWorkspace(r.error);
  const { org_id, connectors } = r.data;

  const go = async (connectorId: string) => {
    render(connectorId);
    // Remember the workspace only once a sign-in is actually started against
    // it, so a stranger probing names cannot overwrite it.
    noteWorkspace(slug);
    const a = await authorize(org_id, connectorId);
    if (a.ok && a.redirectUrl) location.assign(a.redirectUrl);
    else render(undefined, a.error);
  };
  const render = (busy?: string, error?: string) =>
    show(
      ConnectorPicker({
        workspace: slug,
        connectors: connectors as ConnectorInfo[],
        busy,
        error,
        onPick: go,
        onBack: () => askWorkspace(),
      }),
    );

  if (connectors.length === 1) return go(connectors[0].id);
  render();
}

async function finishCallback() {
  const q = new URLSearchParams(location.search);
  const code = q.get("code");
  const state = q.get("state");
  // The code is single-use; get it out of the address bar and history first.
  history.replaceState(null, "", "/");
  if (!code || !state) return askWorkspace(q.get("error_description") ?? "Sign-in was cancelled.");
  const r = await callback(code, state);
  if (!r.ok) return askWorkspace(r.error);
  noteSignedIn();
  location.replace(takeReturnTo() ?? "/");
}

async function boot() {
  if (location.pathname === "/callback") return finishCallback();
  const session = await getSession();
  if (!session) {
    rememberReturnTo(location.pathname + location.search);
    return askWorkspace();
  }
  show(
    SessionCard({
      session,
      onCallApi: async () => {
        const r = await fetch("/api/hello", { credentials: "include" });
        return `${r.status}\n${await r.text()}`;
      },
      onSignOut: async () => {
        await logout();
        askWorkspace();
      },
    }),
  );
}

boot();
