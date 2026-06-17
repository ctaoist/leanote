import { createMemo, createSignal, For, Show, type JSX } from "solid-js";
import {
  ArrowDownUp,
  Check,
  Hash,
  FileText,
  StickyNote,
  MoreVertical,
  Trash2,
  RotateCcw,
  FolderInput,
  Copy,
  Globe,
  Lock,
  Pin,
  PinOff,
  Pencil,
  FileDown,
  ChevronLeft,
  ChevronRight,
} from "lucide-solid";
import { appState, actions, sortNotes, type SortKey, type ViewMode } from "../../state/appStore";
import { isMobile } from "../../lib/responsive";
import { Dropdown, MenuItem, MenuDivider } from "../ui/Dropdown";
import { IconButton } from "../ui/Button";
import { CenteredSpinner } from "../ui/Spinner";
import { formatRelative } from "../../lib/format";
import { BlogMetaModal } from "./BlogMetaModal";
import type { Note, Notebook } from "../../api/types";

const SORT_LABELS: Record<SortKey, string> = {
  updatedDesc: "最近修改",
  updatedAsc: "最早修改",
  createdDesc: "最近创建",
  createdAsc: "最早创建",
  titleAsc: "标题 A→Z",
  titleDesc: "标题 Z→A",
};

export function NoteList() {
  const notebookName = createMemo(
    () => appState.notebooks.find((n) => n.NotebookId === appState.currentNotebookId)?.Title ?? "全部笔记"
  );

  const displayed = createMemo(() => {
    let notes = appState.notes;
    if (appState.activeTag) notes = notes.filter((n) => (n.Tags ?? []).includes(appState.activeTag));
    return sortNotes(notes, appState.sort);
  });

  return (
    <section class="flex h-full flex-col bg-bg">
      {/* 头部 */}
      <div class="flex h-12 shrink-0 items-center justify-between border-b border-border px-3">
        <div class="min-w-0">
          <div class="truncate text-sm font-semibold text-fg">
            {appState.trashView ? "废纸篓" : appState.searchKey ? `搜索：${appState.searchKey}` : notebookName()}
          </div>
          <div class="text-xs text-subtle">{displayed().length} 篇笔记</div>
        </div>

        <Dropdown
          align="right"
          width="190px"
          trigger={({ toggle }) => (
            <IconButton label="排序与视图" onClick={toggle}>
              <ArrowDownUp size={16} />
            </IconButton>
          )}
        >
          {(close) => (
            <>
              <ViewItem mode="snippet" label="摘要视图" close={close} />
              <ViewItem mode="list" label="列表视图" close={close} />
              <MenuDivider />
              <For each={Object.entries(SORT_LABELS) as [SortKey, string][]}>
                {([key, label]) => (
                  <MenuItem
                    active={appState.sort === key}
                    icon={appState.sort === key ? <Check size={14} /> : undefined}
                    onClick={() => actions.setSort(key)}
                  >
                    {label}
                  </MenuItem>
                )}
              </For>
            </>
          )}
        </Dropdown>
      </div>

      {/* 列表 */}
      <div class="flex-1 overflow-y-auto">
        <Show
          when={!appState.loadingNotes}
          fallback={<CenteredSpinner label="加载笔记…" class="pt-16" />}
        >
          <Show
            when={displayed().length}
            fallback={
              <div class="flex flex-col items-center gap-2 px-4 pt-20 text-center text-subtle">
                <StickyNote size={36} class="opacity-40" />
                <p class="text-sm">这里还没有笔记</p>
              </div>
            }
          >
            <ul class="p-2">
              <For each={displayed()}>
                {(note) => <NoteListItem note={note} compact={appState.viewMode === "list"} />}
              </For>
            </ul>
          </Show>
        </Show>
      </div>
    </section>
  );
}

function ViewItem(props: { mode: ViewMode; label: string; close: () => void }) {
  return (
    <MenuItem
      active={appState.viewMode === props.mode}
      icon={appState.viewMode === props.mode ? <Check size={14} /> : undefined}
      onClick={() => actions.setViewMode(props.mode)}
    >
      {props.label}
    </MenuItem>
  );
}

function NoteListItem(props: { note: Note; compact: boolean }) {
  const isActive = () => appState.currentNoteId === props.note.NoteId;
  const title = () => props.note.Title?.trim() || "无标题";
  const tags = () => (props.note.Tags ?? []).filter(Boolean);
  const isBlog = () => !!props.note.IsBlog;
  const isTop = () => !!props.note.IsTop;
  const otherNotebooks = createMemo(() =>
    appState.notebooks.filter((n) => !n.IsTrash && n.NotebookId !== props.note.NotebookId)
  );

  // 二级菜单：null=根菜单，"move"/"copy"=笔记本选择
  const [picker, setPicker] = createSignal<null | "move" | "copy">(null);
  const [metaOpen, setMetaOpen] = createSignal(false);

  const exportPdf = () =>
    window.open(`/note/exportPdf?noteId=${props.note.NoteId}`, "_blank");

  return (
    <li>
      <div
        class={`group relative mb-1 rounded-lg transition-colors
          ${isActive()
            ? "bg-brand-500/10 ring-1 ring-inset ring-brand-500/30"
            : "hover:bg-black/[0.04] dark:hover:bg-white/[0.05]"}`}
      >
        <button
          class="w-full px-3 py-2.5 pr-8 text-left"
          onClick={() => {
            void actions.selectNote(props.note.NoteId);
            if (isMobile()) actions.setMobilePane("editor");
          }}
        >
          <div class="flex items-center gap-1.5">
            <Show when={props.note.IsMarkdown} fallback={<FileText size={13} class="shrink-0 text-subtle" />}>
              <Hash size={13} class="shrink-0 text-brand-500" />
            </Show>
            <span class="truncate text-sm font-medium text-fg">{title()}</span>
            <Show when={isTop()}>
              <Pin size={11} class="shrink-0 text-brand-500" />
            </Show>
            <Show when={isBlog() && !isTop()}>
              <Globe size={11} class="shrink-0 text-subtle" />
            </Show>
          </div>

          <Show when={!props.compact}>
            <p class="mt-1 line-clamp-2 text-xs leading-relaxed text-muted">
              {props.note.Desc?.trim() || "暂无内容"}
            </p>
          </Show>

          <div class="mt-1.5 flex items-center gap-2 text-[11px] text-subtle">
            <span>{formatRelative(props.note.UpdatedTime)}</span>
            <Show when={tags().length}>
              <span class="flex items-center gap-1 truncate">
                <Hash size={10} />
                {tags().slice(0, 3).join(" · ")}
              </span>
            </Show>
          </div>
        </button>

        {/* 行内操作菜单 */}
        <div class="absolute right-1.5 top-2">
          <Dropdown
            align="right"
            width="184px"
            trigger={({ toggle }) => (
              <button
                class="flex h-6 w-6 items-center justify-center rounded text-subtle opacity-0 transition-opacity hover:bg-black/10 group-hover:opacity-100 touch:opacity-100 dark:hover:bg-white/10"
                onClick={(e) => { e.stopPropagation(); setPicker(null); toggle(); }}
              >
                <MoreVertical size={15} />
              </button>
            )}
          >
            {(close) => {
              const closeAll = () => { setPicker(null); close(); };
              return (
                <Show
                  when={!appState.trashView}
                  fallback={
                    <>
                      <MenuItem
                        icon={<RotateCcw size={14} />}
                        onClick={() => { closeAll(); void actions.restoreNote(props.note.NoteId); }}
                      >
                        恢复
                      </MenuItem>
                      <MenuDivider />
                      <MenuItem
                        icon={<Trash2 size={14} />}
                        danger
                        onClick={() => {
                          closeAll();
                          if (confirm(`彻底删除「${title()}」？此操作无法恢复。`)) void actions.purgeNote(props.note.NoteId);
                        }}
                      >
                        彻底删除
                      </MenuItem>
                    </>
                  }
                >
                <Show
                  when={picker() === null}
                  fallback={
                    <NotebookPicker
                      mode={picker()!}
                      notebooks={otherNotebooks()}
                      onBack={() => setPicker(null)}
                      onPick={(nb) => {
                        if (picker() === "move") void actions.moveNote(props.note.NoteId, nb);
                        else void actions.copyNote(props.note.NoteId, nb);
                        closeAll();
                      }}
                    />
                  }
                >
                  {/* 博客 */}
                  <Show
                    when={isBlog()}
                    fallback={
                      <MenuItem
                        icon={<Globe size={14} />}
                        onClick={() => { closeAll(); void actions.setNoteBlog(props.note.NoteId, true, false); }}
                      >
                        设为博客
                      </MenuItem>
                    }
                  >
                    <MenuItem
                      icon={<Lock size={14} />}
                      onClick={() => { closeAll(); void actions.setNoteBlog(props.note.NoteId, false, false); }}
                    >
                      取消公开
                    </MenuItem>
                    <Show
                      when={isTop()}
                      fallback={
                        <MenuItem
                          icon={<Pin size={14} />}
                          onClick={() => { closeAll(); void actions.setNoteBlog(props.note.NoteId, true, true); }}
                        >
                          博客置顶
                        </MenuItem>
                      }
                    >
                      <MenuItem
                        icon={<PinOff size={14} />}
                        onClick={() => { closeAll(); void actions.setNoteBlog(props.note.NoteId, true, false); }}
                      >
                        取消置顶
                      </MenuItem>
                    </Show>
                    <MenuItem
                      icon={<Pencil size={14} />}
                      onClick={() => { closeAll(); setMetaOpen(true); }}
                    >
                      博客信息
                    </MenuItem>
                  </Show>

                  <MenuDivider />

                  {/* 移动 / 复制 */}
                  <Show when={otherNotebooks().length}>
                    <SubmenuItem icon={<FolderInput size={14} />} label="移动到" onClick={() => setPicker("move")} />
                    <SubmenuItem icon={<Copy size={14} />} label="复制到" onClick={() => setPicker("copy")} />
                    <MenuDivider />
                  </Show>

                  {/* 导出 */}
                  <MenuItem icon={<FileDown size={14} />} onClick={() => { closeAll(); exportPdf(); }}>
                    导出 PDF
                  </MenuItem>

                  <MenuDivider />

                  <MenuItem
                    icon={<Trash2 size={14} />}
                    danger
                    onClick={() => {
                      closeAll();
                      if (confirm(`确定删除「${title()}」？`)) void actions.deleteNote(props.note.NoteId);
                    }}
                  >
                    删除笔记
                  </MenuItem>
                </Show>
                </Show>
              );
            }}
          </Dropdown>
        </div>
      </div>
      <Show when={metaOpen()}>
        <BlogMetaModal note={props.note} open={metaOpen()} onClose={() => setMetaOpen(false)} />
      </Show>
    </li>
  );
}

/** 根菜单里指向二级菜单的条目（右侧带箭头） */
function SubmenuItem(props: { icon: JSX.Element; label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      class="flex w-full items-center gap-2.5 px-3 py-2 text-left text-sm text-fg transition-colors hover:bg-black/5 dark:hover:bg-white/5"
    >
      <span class="flex h-4 w-4 items-center justify-center text-muted">{props.icon}</span>
      <span class="flex-1 truncate">{props.label}</span>
      <ChevronRight size={14} class="text-subtle" />
    </button>
  );
}

/** 二级菜单：选择目标笔记本（移动/复制共用） */
function NotebookPicker(props: {
  mode: "move" | "copy";
  notebooks: Notebook[];
  onBack: () => void;
  onPick: (notebookId: string) => void;
}) {
  return (
    <>
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); props.onBack(); }}
        class="flex w-full items-center gap-1.5 px-3 py-2 text-left text-xs font-medium text-subtle transition-colors hover:bg-black/5 dark:hover:bg-white/5"
      >
        <ChevronLeft size={13} />
        {props.mode === "move" ? "移动到" : "复制到"}
      </button>
      <MenuDivider />
      <div class="max-h-56 overflow-y-auto">
        <For each={props.notebooks}>
          {(nb) => (
            <MenuItem onClick={() => props.onPick(nb.NotebookId)}>{nb.Title || "未命名"}</MenuItem>
          )}
        </For>
      </div>
    </>
  );
}
