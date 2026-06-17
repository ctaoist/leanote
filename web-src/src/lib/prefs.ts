// 编辑器偏好（本设备级，存 localStorage；best-effort，私密模式/配额错误忽略）。
// 目前只有「自动保存间隔」，后续编辑器偏好可继续加在这里。
import { createSignal } from "solid-js";

const KEY = "leanote:autoSaveMs";

/** 自动保存防抖间隔（毫秒）默认 / 取值范围 */
export const AUTOSAVE_DEFAULT_MS = 1200;
export const AUTOSAVE_MIN_MS = 500;
export const AUTOSAVE_MAX_MS = 600_000;

function readInitial(): number {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw != null) {
      const n = Number(raw);
      if (Number.isFinite(n) && n >= AUTOSAVE_MIN_MS && n <= AUTOSAVE_MAX_MS) return n;
    }
  } catch {
    /* ignore: storage unavailable */
  }
  return AUTOSAVE_DEFAULT_MS;
}

const [autoSaveMs, setAutoSaveMsSignal] = createSignal(readInitial());

/** 当前自动保存间隔（毫秒）。读取即可，无需在响应式上下文中调用。 */
export { autoSaveMs };

/** 设置自动保存间隔（毫秒，越界自动夹紧）并持久化。 */
export function setAutoSaveMs(ms: number): void {
  const clamped = Math.min(AUTOSAVE_MAX_MS, Math.max(AUTOSAVE_MIN_MS, Math.round(ms)));
  setAutoSaveMsSignal(clamped);
  try {
    localStorage.setItem(KEY, String(clamped));
  } catch {
    /* ignore: storage unavailable */
  }
}
