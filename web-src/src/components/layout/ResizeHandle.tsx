import { createSignal, onCleanup } from "solid-js";

interface ResizeHandleProps {
  /** 拖动时回调，dx 为相对上一次的水平位移 */
  onResize: (dx: number) => void;
  onDone?: () => void;
}

/** 竖向分隔条：拖动以调整左侧面板宽度 */
export function ResizeHandle(props: ResizeHandleProps) {
  const [active, setActive] = createSignal(false);
  let lastX = 0;

  const onMove = (e: PointerEvent) => {
    const dx = e.clientX - lastX;
    lastX = e.clientX;
    if (dx !== 0) props.onResize(dx);
  };
  const onUp = () => {
    setActive(false);
    document.removeEventListener("pointermove", onMove);
    document.removeEventListener("pointerup", onUp);
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
    props.onDone?.();
  };
  const onDown = (e: PointerEvent) => {
    e.preventDefault();
    lastX = e.clientX;
    setActive(true);
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onUp);
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  };

  onCleanup(() => {
    document.removeEventListener("pointermove", onMove);
    document.removeEventListener("pointerup", onUp);
  });

  return (
    <div
      class="group relative z-10 w-px shrink-0 bg-border"
      onPointerDown={onDown}
    >
      <div
        class={`absolute inset-y-0 -left-1.5 -right-1.5 cursor-col-resize transition-colors
          ${active() ? "bg-brand-500/30" : "group-hover:bg-brand-500/20"}`}
      />
    </div>
  );
}
