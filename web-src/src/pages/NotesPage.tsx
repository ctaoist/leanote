import { createEffect, createSignal, onMount, onCleanup, Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { Minimize2 } from "lucide-solid";
import { appState, actions } from "../state/appStore";
import { isMobile } from "../lib/responsive";
import { AppHeader } from "../components/layout/AppHeader";
import { NotebookPanel } from "../components/notebook/NotebookPanel";
import { NoteList } from "../components/notelist/NoteList";
import { NoteEditor } from "../components/editor/NoteEditor";
import { ResizeHandle } from "../components/layout/ResizeHandle";
import { CenteredSpinner } from "../components/ui/Spinner";

const LS_NB = "leanote-w-notebook";
const LS_NL = "leanote-w-notelist";
const clamp = (v: number, min: number, max: number) => Math.min(Math.max(v, min), max);

export default function NotesPage() {
  const navigate = useNavigate();

  const [nbWidth, setNbWidth] = createSignal(Number(localStorage.getItem(LS_NB)) || 240);
  const [nlWidth, setNlWidth] = createSignal(Number(localStorage.getItem(LS_NL)) || 300);

  onMount(() => {
    void actions.bootstrap();
  });

  // 会话失效 / 未登录 → 跳登录
  createEffect(() => {
    if (appState.authExpired) {
      navigate(`/login?from=${encodeURIComponent("/note")}`, { replace: true });
    }
  });

  // 保存列宽
  createEffect(() => localStorage.setItem(LS_NB, String(nbWidth())));
  createEffect(() => localStorage.setItem(LS_NL, String(nlWidth())));

  // 离开页面前若有未保存内容则保存
  const beforeUnload = () => {
    if (appState.dirty) void actions.saveNow();
  };
  window.addEventListener("beforeunload", beforeUnload);

  // 键盘快捷键：⌘/Ctrl+S 保存，⌘/Ctrl+E 切换只读/编辑，⌘/Ctrl+Shift+F 沉浸模式，Esc 退出沉浸
  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Escape" && appState.immersive) {
      actions.setImmersive(false);
      return;
    }
    const mod = e.metaKey || e.ctrlKey;
    if (!mod) return;
    const key = e.key.toLowerCase();
    if (key === "s") {
      e.preventDefault();
      void actions.saveNow();
    } else if (key === "e") {
      e.preventDefault();
      if (appState.currentNote) actions.setEditing(!appState.editing);
    } else if (key === "f" && e.shiftKey) {
      e.preventDefault();
      if (appState.currentNote) actions.toggleImmersive();
    }
  };
  window.addEventListener("keydown", onKeyDown);

  onCleanup(() => {
    window.removeEventListener("beforeunload", beforeUnload);
    window.removeEventListener("keydown", onKeyDown);
    if (appState.dirty) void actions.saveNow();
  });

  return (
    <div class="flex h-screen flex-col overflow-hidden bg-bg">
      <Show when={!appState.immersive}>
        <AppHeader />
      </Show>

      <Show
        when={appState.immersive}
        fallback={
          <Show
            when={isMobile()}
            fallback={
              <div class="flex min-h-0 flex-1">
                {/* 左：笔记本树 */}
                <Show when={!appState.leftCollapsed}>
                  <div class="shrink-0 overflow-hidden" style={{ width: `${nbWidth()}px` }}>
                    <NotebookPanel />
                  </div>
                  <ResizeHandle onResize={(dx) => setNbWidth((w) => clamp(w + dx, 180, 420))} />
                </Show>

                {/* 中：笔记列表 */}
                <div class="shrink-0 overflow-hidden" style={{ width: `${nlWidth()}px` }}>
                  <NoteList />
                </div>
                <ResizeHandle onResize={(dx) => setNlWidth((w) => clamp(w + dx, 220, 520))} />

                {/* 右：编辑器 */}
                <div class="min-w-0 flex-1">
                  <Show when={appState.ready} fallback={<CenteredSpinner label="正在载入工作区…" />}>
                    <NoteEditor />
                  </Show>
                </div>
              </div>
            }
          >
            {/* 移动端：单栏切换（列表 ↔ 编辑器）+ 笔记本抽屉 */}
            <div class="relative flex min-h-0 flex-1 flex-col">
              <div class="min-h-0 flex-1">
                <Show when={appState.mobilePane === "editor"} fallback={<NoteList />}>
                  <Show when={appState.ready} fallback={<CenteredSpinner label="正在载入工作区…" />}>
                    <NoteEditor />
                  </Show>
                </Show>
              </div>

              <Show when={appState.nbDrawerOpen}>
                <div class="absolute inset-0 z-30 flex">
                  <div class="h-full w-72 max-w-[82%] animate-[slideInLeft_.18s_ease] overflow-hidden border-r border-border bg-surface shadow-2xl">
                    <NotebookPanel />
                  </div>
                  <button
                    type="button"
                    aria-label="关闭笔记本"
                    class="flex-1 animate-[fadeIn_.18s_ease] bg-black/40"
                    onClick={() => actions.setNbDrawer(false)}
                  />
                </div>
              </Show>
            </div>
          </Show>
        }
      >
        {/* 沉浸写作：隐藏顶栏与两侧，仅居中编辑器 */}
        <div class="relative min-h-0 flex-1">
          <button
            type="button"
            title="退出沉浸（Esc）"
            onClick={() => actions.setImmersive(false)}
            class="absolute right-4 top-4 z-10 flex h-9 w-9 items-center justify-center rounded-lg text-muted transition-colors hover:bg-black/5 hover:text-fg dark:hover:bg-white/5"
          >
            <Minimize2 size={18} />
          </button>
          <div class="mx-auto h-full max-w-3xl">
            <Show when={appState.ready} fallback={<CenteredSpinner label="正在载入工作区…" />}>
              <NoteEditor />
            </Show>
          </div>
        </div>
      </Show>
    </div>
  );
}
