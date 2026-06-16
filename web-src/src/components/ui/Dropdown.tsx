import { createSignal, onCleanup, Show, type JSX } from "solid-js";

interface DropdownProps {
  trigger: (api: { open: boolean; toggle: () => void }) => JSX.Element;
  children: JSX.Element | ((close: () => void) => JSX.Element);
  align?: "left" | "right";
  width?: string;
  class?: string;
}

export function Dropdown(props: DropdownProps) {
  const [open, setOpen] = createSignal(false);
  let root: HTMLDivElement | undefined;

  const close = () => setOpen(false);
  const toggle = () => setOpen((v) => !v);

  const onDocClick = (e: MouseEvent) => {
    if (root && !root.contains(e.target as Node)) close();
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "Escape") close();
  };
  document.addEventListener("mousedown", onDocClick);
  document.addEventListener("keydown", onKey);
  onCleanup(() => {
    document.removeEventListener("mousedown", onDocClick);
    document.removeEventListener("keydown", onKey);
  });

  return (
    <div class="relative" ref={root}>
      {props.trigger({ get open() { return open(); }, toggle })}
      <Show when={open()}>
        <div
          class={`absolute z-40 mt-1.5 overflow-hidden rounded-lg border border-border bg-elevated py-1 shadow-pop
            ${props.align === "left" ? "left-0" : "right-0"} ${props.class ?? ""}`}
          style={{ "min-width": props.width ?? "180px" }}
        >
          {typeof props.children === "function" ? props.children(close) : props.children}
        </div>
      </Show>
    </div>
  );
}

interface MenuItemProps {
  onClick?: () => void;
  icon?: JSX.Element;
  danger?: boolean;
  active?: boolean;
  children: JSX.Element;
}

export function MenuItem(props: MenuItemProps) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      class={`flex w-full items-center gap-2.5 px-3 py-2 text-left text-sm transition-colors
        hover:bg-black/5 dark:hover:bg-white/5
        ${props.danger ? "text-red-500" : "text-fg"}
        ${props.active ? "font-medium text-brand-600" : ""}`}
    >
      <Show when={props.icon}>
        <span class="flex h-4 w-4 items-center justify-center text-muted">{props.icon}</span>
      </Show>
      <span class="flex-1 truncate">{props.children}</span>
    </button>
  );
}

export function MenuDivider() {
  return <div class="my-1 h-px bg-border" />;
}
