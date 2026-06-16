import { Leaf } from "lucide-solid";

export function BrandMark(props: { size?: number; class?: string }) {
  const s = () => props.size ?? 28;
  return (
    <span
      class={`inline-flex items-center justify-center rounded-xl bg-brand-500 text-white ${props.class ?? ""}`}
      style={{ width: `${s() * 1.4}px`, height: `${s() * 1.4}px` }}
    >
      <Leaf size={s()} fill="currentColor" stroke-width={1.5} />
    </span>
  );
}

export function BrandLogo(props: { size?: number; class?: string; subtitle?: boolean }) {
  return (
    <div class={`flex items-center gap-2.5 ${props.class ?? ""}`}>
      <BrandMark size={props.size ?? 22} />
      <div class="leading-none">
        <div class="text-lg font-bold tracking-tight text-fg">
          Leanote<span class="text-brand-500">.</span>
        </div>
        {props.subtitle && <div class="mt-0.5 text-[11px] text-subtle">蚂蚁笔记</div>}
      </div>
    </div>
  );
}
