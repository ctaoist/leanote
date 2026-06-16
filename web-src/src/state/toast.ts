import { createSignal } from "solid-js";

export type ToastKind = "info" | "success" | "error";
export interface Toast {
  id: number;
  message: string;
  kind: ToastKind;
}

const [toasts, setToasts] = createSignal<Toast[]>([]);
export { toasts };

let seq = 0;

export function pushToast(message: string, kind: ToastKind = "info", timeout = 3200) {
  const id = ++seq;
  setToasts((prev) => [...prev, { id, message, kind }]);
  if (timeout > 0) {
    setTimeout(() => dismissToast(id), timeout);
  }
  return id;
}

export function dismissToast(id: number) {
  setToasts((prev) => prev.filter((t) => t.id !== id));
}
