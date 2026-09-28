import type { ConnectorInfo } from "identity";
import { h } from "../dom";

// Step two: which identity provider. One button per connector the workspace
// offers; a workspace with exactly one skips this step entirely (see main.ts).
export function ConnectorPicker(props: {
  workspace: string;
  connectors: ConnectorInfo[];
  busy?: string;
  error?: string;
  onPick(connectorId: string): void;
  onBack(): void;
}): HTMLElement {
  return h(
    "section",
    { class: "card" },
    h("h1", {}, `Sign in to ${props.workspace}`),
    props.connectors.length === 0 && h("p", {}, "This workspace has no sign-in methods yet."),
    ...props.connectors.map((c) =>
      h(
        "button",
        { class: "provider", disabled: !!props.busy, onclick: () => props.onPick(c.id) },
        props.busy === c.id ? "Redirecting…" : `Continue with ${c.name}`,
      ),
    ),
    props.error && h("p", { class: "error", role: "alert" }, props.error),
    h("button", { type: "button", class: "link", onclick: props.onBack }, "Back"),
  );
}
