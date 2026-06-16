// 视口断点：是否处于「移动端」（窄屏）。低于 lg(1024px) 视为移动端，
// 此时三栏布局收敛为单栏切换 + 笔记本抽屉。模块级单例信号，随窗口变化更新，
// 供布局组件（NotesPage / AppHeader / NoteList / NotebookPanel / NoteEditor）共享。
import { createSignal } from "solid-js";

const QUERY = "(max-width: 1023px)";

function initial(): boolean {
  return typeof window !== "undefined" && window.matchMedia(QUERY).matches;
}

const [isMobile, setIsMobile] = createSignal(initial());

if (typeof window !== "undefined") {
  const mq = window.matchMedia(QUERY);
  const onChange = (e: MediaQueryList | MediaQueryListEvent) => setIsMobile(e.matches);
  // Safari <14 仅支持 addListener
  if (mq.addEventListener) mq.addEventListener("change", onChange);
  else mq.addListener(onChange);
}

export { isMobile };
