import { Show, type JSX, type ParentComponent } from "solid-js";
import { Portal } from "solid-js/web";
import { X } from "lucide-solid";
import { IconButton } from "./Button";

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title?: string;
  footer?: JSX.Element;
  width?: string;
}

export const Modal: ParentComponent<ModalProps> = (props) => {
  return (
    <Show when={props.open}>
      <Portal>
        <div
          class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 animate-[fadeIn_.15s_ease]"
          onClick={(e) => {
            if (e.target === e.currentTarget) props.onClose();
          }}
        >
          <div
            class="w-full overflow-hidden rounded-xl border border-border bg-surface shadow-pop"
            style={{ "max-width": props.width ?? "440px" }}
            role="dialog"
            aria-modal="true"
          >
            <Show when={props.title}>
              <div class="flex items-center justify-between border-b border-border px-5 py-3.5">
                <h3 class="text-base font-semibold text-fg">{props.title}</h3>
                <IconButton label="关闭" onClick={props.onClose}>
                  <X size={18} />
                </IconButton>
              </div>
            </Show>
            <div class="px-5 py-4">{props.children}</div>
            <Show when={props.footer}>
              <div class="flex justify-end gap-2 border-t border-border px-5 py-3.5">
                {props.footer}
              </div>
            </Show>
          </div>
        </div>
      </Portal>
    </Show>
  );
};
