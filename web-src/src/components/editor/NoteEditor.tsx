import { Show, createSignal, lazy, Suspense } from "solid-js";
import {
  Trash2,
  Hash,
  FileText,
  Eye,
  Pencil,
  Clock,
  History,
  Paperclip,
  Maximize2,
  Minimize2,
  ChevronLeft,
} from "lucide-solid";
import { appState, actions } from "../../state/appStore";
import { isMobile } from "../../lib/responsive";
import { IconButton } from "../ui/Button";
import { CenteredSpinner } from "../ui/Spinner";
import { TagEditor } from "./TagEditor";
import { AttachmentsModal } from "./AttachmentsModal";
import { formatDateTime } from "../../lib/format";

// 两个编辑器各自较重（TipTap+ProseMirror / CodeMirror+markdown-it+Prism），且每篇
// 笔记只用其一，故按需懒加载 —— 把它们从初始 NotesPage chunk 拆出。
const RichTextEditor = lazy(() =>
  import("./RichTextEditor").then((m) => ({ default: m.RichTextEditor }))
);
const MarkdownEditor = lazy(() =>
  import("./MarkdownEditor").then((m) => ({ default: m.MarkdownEditor }))
);
// 历史弹窗静态引用了 markdown 渲染管线（markdown-it+katex+Prism ≈690KB）。懒加载它，
// 使该管线不再随 NotesPage 初始加载，只在打开历史 / markdown 笔记时才拉取。
const HistoryModal = lazy(() =>
  import("./HistoryModal").then((m) => ({ default: m.HistoryModal }))
);

export function NoteEditor() {
  const [showHistory, setShowHistory] = createSignal(false);
  const [showAttach, setShowAttach] = createSignal(false);

  return (
    <div class="flex h-full flex-col bg-surface">
      <Show
        when={appState.currentNote}
        fallback={
          <Show when={!appState.loadingNote} fallback={<CenteredSpinner label="加载笔记…" />}>
            <EmptyEditor />
          </Show>
        }
      >
        {(note) => (
          <>
            {/* 工具条 */}
            <div class="flex h-12 shrink-0 items-center justify-between border-b border-border px-4">
              <div class="flex items-center gap-2 text-xs text-subtle">
                <Show when={isMobile()}>
                  <IconButton label="返回列表" onClick={() => actions.setMobilePane("list")}>
                    <ChevronLeft size={18} />
                  </IconButton>
                </Show>
                <Show when={note().IsMarkdown} fallback={<FileText size={14} />}>
                  <Hash size={14} class="text-brand-500" />
                </Show>
                <span>{note().IsMarkdown ? "Markdown" : "富文本"}</span>
                <span class="hidden items-center gap-1 sm:flex">
                  <Clock size={12} /> {formatDateTime(note().UpdatedTime)}
                </span>
              </div>
              <div class="flex items-center gap-1">
                <IconButton label="历史版本" onClick={() => setShowHistory(true)}>
                  <History size={16} />
                </IconButton>
                <div class="relative">
                  <IconButton label="附件" active={showAttach()} onClick={() => setShowAttach(true)}>
                    <Paperclip size={16} />
                  </IconButton>
                  <Show when={(note().AttachNum ?? 0) > 0}>
                    <span class="pointer-events-none absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-brand-500 px-1 text-[10px] font-semibold leading-none text-white">
                      {note().AttachNum}
                    </span>
                  </Show>
                </div>
                <IconButton
                  label={appState.immersive ? "退出沉浸" : "沉浸写作"}
                  active={appState.immersive}
                  onClick={() => actions.toggleImmersive()}
                >
                  <Show when={appState.immersive} fallback={<Maximize2 size={16} />}>
                    <Minimize2 size={16} />
                  </Show>
                </IconButton>
                <div class="mx-1 h-5 w-px bg-border" />
                <IconButton
                  label={appState.editing ? "切换只读" : "切换编辑"}
                  active={appState.editing}
                  onClick={() => actions.setEditing(!appState.editing)}
                >
                  <Show when={appState.editing} fallback={<Eye size={16} />}>
                    <Pencil size={16} />
                  </Show>
                </IconButton>
                <IconButton
                  label="删除笔记"
                  onClick={() => {
                    if (confirm("确定删除这篇笔记？")) void actions.deleteNote(note().NoteId);
                  }}
                >
                  <Trash2 size={16} />
                </IconButton>
              </div>
            </div>

            {/* 标题 + 标签 */}
            <div class="shrink-0 px-4 pt-5 sm:px-6">
              <input
                class="w-full bg-transparent text-2xl font-bold text-fg placeholder:text-subtle focus:outline-none disabled:cursor-default"
                placeholder="无标题"
                value={note().Title ?? ""}
                disabled={!appState.editing}
                onInput={(e) => actions.patchCurrent({ Title: e.currentTarget.value })}
              />
              <div class="mt-3">
                <TagEditor tags={(note().Tags ?? []).filter(Boolean)} onChange={(tags) => actions.patchCurrent({ Tags: tags })} />
              </div>
            </div>

            {/* 编辑器主体 */}
            <div class="mt-2 min-h-0 flex-1">
              <Suspense fallback={<CenteredSpinner label="加载编辑器…" />}>
                <Show
                  when={note().IsMarkdown}
                  fallback={
                    <RichTextEditor
                      noteId={note().NoteId}
                      content={note().Content ?? ""}
                      editable={appState.editing}
                      onChange={(html) => actions.patchCurrent({ Content: html })}
                    />
                  }
                >
                  <MarkdownEditor
                    noteId={note().NoteId}
                    content={note().Content ?? ""}
                    editable={appState.editing}
                    onChange={(md) => actions.patchCurrent({ Content: md })}
                  />
                </Show>
              </Suspense>
            </div>

            <Show when={showHistory()}>
              <Suspense>
                <HistoryModal
                  noteId={note().NoteId}
                  isMarkdown={!!note().IsMarkdown}
                  open={showHistory()}
                  onClose={() => setShowHistory(false)}
                  onRestore={(content) => actions.patchCurrent({ Content: content })}
                />
              </Suspense>
            </Show>
            <AttachmentsModal
              noteId={note().NoteId}
              open={showAttach()}
              onClose={() => setShowAttach(false)}
              onCountChange={(n) => actions.setAttachNum(n)}
            />
          </>
        )}
      </Show>
    </div>
  );
}

function EmptyEditor() {
  return (
    <div class="flex h-full flex-col items-center justify-center gap-4 text-center text-subtle">
      <FileText size={48} class="opacity-30" />
      <div>
        <p class="text-sm">选择一篇笔记，或新建一篇</p>
        <div class="mt-4 flex items-center justify-center gap-2">
          <button class="btn-outline h-9 text-sm" onClick={() => void actions.createNote(false)}>
            新建富文本
          </button>
          <button class="btn-primary h-9 text-sm" onClick={() => void actions.createNote(true)}>
            新建 Markdown
          </button>
        </div>
      </div>
    </div>
  );
}
