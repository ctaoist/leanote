import { splitProps, type JSX, type ParentComponent } from "solid-js";

type Variant = "primary" | "outline" | "ghost";
type Size = "sm" | "md";

interface ButtonProps extends JSX.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

const variantClass: Record<Variant, string> = {
  primary: "btn-primary",
  outline: "btn-outline",
  ghost: "btn-ghost",
};

export const Button: ParentComponent<ButtonProps> = (props) => {
  const [local, rest] = splitProps(props, ["variant", "size", "class", "children"]);
  const sizeClass = local.size === "sm" ? "h-8 px-3 text-xs" : "";
  return (
    <button
      class={`${variantClass[local.variant ?? "primary"]} ${sizeClass} ${local.class ?? ""}`}
      {...rest}
    >
      {local.children}
    </button>
  );
};

interface IconButtonProps extends JSX.ButtonHTMLAttributes<HTMLButtonElement> {
  label?: string;
  active?: boolean;
}

export const IconButton: ParentComponent<IconButtonProps> = (props) => {
  const [local, rest] = splitProps(props, ["class", "children", "label", "active"]);
  return (
    <button
      type="button"
      title={local.label}
      aria-label={local.label}
      class={`inline-flex h-9 w-9 items-center justify-center rounded-lg text-muted
        transition-colors hover:bg-black/5 hover:text-fg dark:hover:bg-white/5
        focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/40
        disabled:opacity-40 disabled:pointer-events-none
        ${local.active ? "bg-brand-500/10 text-brand-600" : ""} ${local.class ?? ""}`}
      {...rest}
    >
      {local.children}
    </button>
  );
};
