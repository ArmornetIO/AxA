import type { Session } from "axa";
import { h } from "../dom";

// Signed in: who the cookie says you are, one protected call to prove the API
// agrees, and sign-out.
export function SessionCard(props: {
  session: Session;
  onCallApi(): Promise<string>;
  onSignOut(): void;
}): HTMLElement {
  const out = h("pre", { class: "out" });
  return h(
    "section",
    { class: "card" },
    h("h1", {}, "Signed in"),
    h(
      "dl",
      {},
      h("dt", {}, "Subject"),
      h("dd", {}, props.session.subject),
      h("dt", {}, "Workspace"),
      h("dd", {}, props.session.org_name || props.session.org_id || "none"),
      h("dt", {}, "Role"),
      h("dd", {}, props.session.org_role || "—"),
    ),
    h(
      "button",
      { onclick: async () => (out.textContent = await props.onCallApi()) },
      "GET /api/hello",
    ),
    out,
    h("button", { type: "button", class: "link", onclick: props.onSignOut }, "Sign out"),
  );
}
