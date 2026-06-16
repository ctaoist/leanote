import { For } from "solid-js";
import { Portal } from "solid-js/web";
import { CheckCircle2, AlertCircle, Info, X } from "lucide-solid";
import { toasts, dismissToast, type ToastKind } from "../../state/toast";

const icons: Record<ToastKind, typeof Info> = {
  info: Info,
  success: CheckCircle2,
  error: AlertCircle,
};

const accent: Record<ToastKind, string> = {
  info: "text-sky-500",
  success: "text-brand-500",
  error: "text-red-500",
};

export function Toaster() {
  return (
    <Portal>
      <div class="pointer-events-none fixed bottom-5 right-5 z-[60] flex flex-col gap-2">
        <For each={toasts()}>
          {(toast) => {
            const Icon = icons[toast.kind];
            return (
              <div class="pointer-events-auto flex items-start gap-2.5 rounded-lg border border-border bg-elevated px-3.5 py-2.5 shadow-pop animate-[fadeInUp_.18s_ease]">
                <Icon size={18} class={`mt-0.5 shrink-0 ${accent[toast.kind]}`} />
                <span class="max-w-xs text-sm text-fg">{toast.message}</span>
                <button
                  class="ml-1 shrink-0 text-subtle hover:text-fg"
                  onClick={() => dismissToast(toast.id)}
                  aria-label="关闭"
                >
                  <X size={15} />
                </button>
              </div>
            );
          }}
        </For>
      </div>
    </Portal>
  );
}
