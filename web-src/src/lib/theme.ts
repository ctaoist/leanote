import { createSignal } from "solid-js";

const STORAGE_KEY = "leanote-theme";

function readInitial(): boolean {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved === "dark") return true;
  if (saved === "light") return false;
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false;
}

const [isDark, setIsDark] = createSignal(readInitial());

function apply(dark: boolean) {
  document.documentElement.classList.toggle("dark", dark);
}

/** 在应用启动时调用一次，使 DOM 与已保存的偏好一致 */
export function initTheme() {
  apply(isDark());
}

export function toggleDark() {
  const next = !isDark();
  setIsDark(next);
  localStorage.setItem(STORAGE_KEY, next ? "dark" : "light");
  apply(next);
}

export { isDark };
