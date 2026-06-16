import { createMemo, Show } from "solid-js";

interface AvatarProps {
  src?: string;
  name?: string;
  size?: number;
  class?: string;
}

const PALETTE = [
  "bg-brand-500",
  "bg-sky-500",
  "bg-violet-500",
  "bg-amber-500",
  "bg-rose-500",
  "bg-emerald-500",
];

export function Avatar(props: AvatarProps) {
  const size = () => props.size ?? 32;
  const initial = createMemo(() => (props.name?.trim()?.[0] ?? "?").toUpperCase());
  const color = createMemo(() => {
    const n = props.name ?? "";
    let h = 0;
    for (let i = 0; i < n.length; i++) h = (h + n.charCodeAt(i)) % PALETTE.length;
    return PALETTE[h];
  });

  return (
    <Show
      when={props.src}
      fallback={
        <div
          class={`flex items-center justify-center rounded-full font-semibold text-white ${color()} ${props.class ?? ""}`}
          style={{ width: `${size()}px`, height: `${size()}px`, "font-size": `${size() * 0.42}px` }}
        >
          {initial()}
        </div>
      }
    >
      <img
        src={props.src}
        alt={props.name ?? "avatar"}
        class={`rounded-full object-cover ${props.class ?? ""}`}
        style={{ width: `${size()}px`, height: `${size()}px` }}
      />
    </Show>
  );
}
