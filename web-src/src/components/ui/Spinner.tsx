import type { JSX } from "solid-js";

export function Spinner(props: { class?: string }) {
  return (
    <svg
      class={`animate-spin ${props.class ?? "h-5 w-5"}`}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle class="opacity-20" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
      <path
        class="opacity-90"
        fill="currentColor"
        d="M4 12a8 8 0 0 1 8-8v4a4 4 0 0 0-4 4H4z"
      />
    </svg>
  );
}

export function CenteredSpinner(props: { label?: string; class?: string }): JSX.Element {
  return (
    <div class={`flex h-full w-full flex-col items-center justify-center gap-3 text-subtle ${props.class ?? ""}`}>
      <Spinner class="h-6 w-6 text-brand-500" />
      {props.label && <span class="text-sm">{props.label}</span>}
    </div>
  );
}
