import { h } from "../dom";

// Step one: which workspace. Prefilled from what this browser used last, with
// a way out for someone who belongs to more than one.
export function WorkspaceStep(props: {
  remembered?: string;
  error?: string;
  onSubmit(slug: string): void;
  onForget(): void;
}): HTMLElement {
  const input = h("input", {
    id: "workspace",
    name: "workspace",
    value: props.remembered ?? "",
    placeholder: "demo",
    autocomplete: "organization",
    required: true,
    autofocus: true,
  });
  const form = h(
    "form",
    { class: "card" },
    h("h1", {}, "Sign in"),
    h("label", { htmlFor: "workspace" }, "Workspace"),
    input,
    props.error && h("p", { class: "error", role: "alert" }, props.error),
    h("button", { type: "submit" }, "Continue"),
    props.remembered &&
      h("button", { type: "button", class: "link", onclick: props.onForget }, "Use a different workspace"),
  );
  form.onsubmit = (e) => {
    e.preventDefault();
    const slug = input.value.trim().toLowerCase();
    if (slug) props.onSubmit(slug);
  };
  return form;
}
