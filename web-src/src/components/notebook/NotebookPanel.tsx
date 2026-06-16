import { createEffect, createMemo, createSignal, For, Show, type JSX } from "solid-js";
import {
  Book,
  ChevronRight,
  ChevronLeft,
  Plus,
  MoreHorizontal,
  Pencil,
  Trash2,
  Hash,
  FileText,
  FolderPlus,
  FolderInput,
  CornerLeftUp,
} from "lucide-solid";
import { appState, actions, buildNotebookTree, deriveTags, type NotebookNode } from "../../state/appStore";
import { isMobile } from "../../lib/responsive";
import { Dropdown, MenuItem, MenuDivider } from "../ui/Dropdown";

// 拖拽排序的跨实例共享状态（被拖的笔记本 id / 当前 drop 目标 id）。
const [draggingId, setDraggingId] = createSignal<string | null>(null);
const [dropTargetId, setDropTargetId] = createSignal<string | null>(null);

export function NotebookPanel() {
  const tree = createMemo(() => buildNotebookTree(appState.notebooks.filter((n) => !n.IsTrash)));
  const tags = createMemo(() => deriveTags(appState.notes));

  const [expanded, setExpanded] = createSignal<Set<string>>(new Set());
  const [adding, setAdding] = createSignal(false);
  const [newTitle, setNewTitle] = createSignal("");

  const toggleExpand = (id: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  // 选中的笔记本（含恢复上次状态时）若是嵌套的，展开其所有祖先使其在树中可见。
  createEffect(() => {
    const cur = appState.currentNotebookId;
    const nbs = appState.notebooks;
    if (!cur) return;
    const byId = new Map(nbs.map((n) => [n.NotebookId, n]));
    const anc = new Set<string>();
    let pid = byId.get(cur)?.ParentNotebookId;
    while (pid && !anc.has(pid)) {
      anc.add(pid);
      pid = byId.get(pid)?.ParentNotebookId;
    }
    if (anc.size) setExpanded((prev) => new Set([...prev, ...anc]));
  });

  const submitNew = () => {
    const title = newTitle().trim();
    if (title) void actions.createNotebook(title);
    setNewTitle("");
    setAdding(false);
  };

  return (
    <aside class="flex h-full flex-col bg-surface">
      {/* 笔记本区头 */}
      <div class="flex items-center justify-between px-4 pb-2 pt-4">
        <div class="flex items-center gap-2 text-sm font-semibold text-fg">
          <Book size={16} class="text-brand-500" />
          笔记本
        </div>
        <button
          class="flex h-6 w-6 items-center justify-center rounded-md text-muted hover:bg-brand-500/10 hover:text-brand-600"
          title="新建笔记本"
          onClick={() => setAdding((v) => !v)}
        >
          <Plus size={16} />
        </button>
      </div>

      <Show when={adding()}>
        <div class="px-3 pb-2">
          <input
            class="input h-8 text-sm"
            placeholder="笔记本名称，回车确认"
            value={newTitle()}
            autofocus
            onInput={(e) => setNewTitle(e.currentTarget.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") submitNew();
              if (e.key === "Escape") setAdding(false);
            }}
            onBlur={submitNew}
          />
        </div>
      </Show>

      {/* 树 */}
      <div class="flex-1 overflow-y-auto px-2 pb-3">
        <Show
          when={tree().length}
          fallback={<EmptyHint text={appState.loadingNotebooks ? "加载中…" : "暂无笔记本"} />}
        >
          <For each={tree()}>
            {(node) => (
              <NotebookItem node={node} expanded={expanded()} onToggle={toggleExpand} />
            )}
          </For>
        </Show>

        {/* 废纸篓 */}
        <button
          class={`mt-1 flex w-full items-center gap-2 rounded-lg py-1.5 pl-7 pr-2 text-left text-sm transition-colors
            ${appState.trashView
              ? "bg-brand-500/10 font-medium text-brand-700"
              : "text-fg hover:bg-black/[0.04] dark:hover:bg-white/[0.04]"}`}
          onClick={() => {
            void actions.showTrash();
            if (isMobile()) {
              actions.setMobilePane("list");
              actions.setNbDrawer(false);
            }
          }}
        >
          <Trash2 size={14} class="shrink-0 text-subtle" />
          <span class="truncate">废纸篓</span>
        </button>

        {/* 标签 */}
        <Show when={tags().length}>
          <div class="mt-4 px-2 pb-1 text-xs font-semibold uppercase tracking-wide text-subtle">标签</div>
          <div class="flex flex-wrap gap-1.5 px-2">
            <For each={tags()}>
              {(t) => (
                <button
                  class={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs transition-colors
                    ${appState.activeTag === t.tag
                      ? "border-brand-500 bg-brand-500/10 text-brand-600"
                      : "border-border text-muted hover:border-brand-400 hover:text-brand-600"}`}
                  onClick={() => actions.setActiveTag(t.tag)}
                >
                  <Hash size={11} />
                  {t.tag}
                  <span class="text-subtle">{t.count}</span>
                </button>
              )}
            </For>
          </div>
        </Show>
      </div>
    </aside>
  );
}

function NotebookItem(props: {
  node: NotebookNode;
  expanded: Set<string>;
  onToggle: (id: string) => void;
}) {
  const node = props.node;
  const hasChildren = () => node.children.length > 0;
  const isOpen = () => props.expanded.has(node.NotebookId);
  const isActive = () => appState.currentNotebookId === node.NotebookId;
  const [renaming, setRenaming] = createSignal(false);
  const [title, setTitle] = createSignal(node.Title);
  // 二级菜单：null=根菜单，"move"=选择目标笔记本
  const [picker, setPicker] = createSignal<null | "move">(null);
  // 行内新建子笔记本
  const [addingChild, setAddingChild] = createSignal(false);
  const [childTitle, setChildTitle] = createSignal("");

  // 移动目标：排除自身及其所有后代（避免成环），排除回收站。
  const descendantIds = createMemo(() => {
    const set = new Set<string>();
    const walk = (n: NotebookNode) => {
      set.add(n.NotebookId);
      n.children.forEach(walk);
    };
    walk(node);
    return set;
  });
  const moveTargets = createMemo(() =>
    appState.notebooks.filter((n) => !n.IsTrash && !descendantIds().has(n.NotebookId))
  );

  const submitRename = () => {
    const t = title().trim();
    if (t && t !== node.Title) void actions.renameNotebook(node.NotebookId, t);
    setRenaming(false);
  };

  const startAddChild = () => {
    setChildTitle("");
    setAddingChild(true);
    if (hasChildren() && !isOpen()) props.onToggle(node.NotebookId);
  };
  const submitChild = () => {
    const t = childTitle().trim();
    setAddingChild(false);
    setChildTitle("");
    if (t) {
      void actions.createNotebook(t, node.NotebookId);
      if (!isOpen()) props.onToggle(node.NotebookId); // 展开父，使新子笔记本可见
    }
  };

  return (
    <div>
      <div
        class={`group flex items-center gap-1 rounded-lg pr-1 transition-colors
          ${isActive() ? "bg-brand-500/10" : "hover:bg-black/[0.04] dark:hover:bg-white/[0.04]"}
          ${dropTargetId() === node.NotebookId ? "ring-2 ring-inset ring-brand-500/60" : ""}`}
        style={{ "padding-left": `${node.depth * 14 + 4}px` }}
        draggable={!renaming()}
        onDragStart={(e) => {
          e.stopPropagation();
          if (e.dataTransfer) e.dataTransfer.effectAllowed = "move";
          setDraggingId(node.NotebookId);
        }}
        onDragEnd={() => { setDraggingId(null); setDropTargetId(null); }}
        onDragOver={(e) => {
          const d = draggingId();
          if (d && d !== node.NotebookId) {
            e.preventDefault();
            if (e.dataTransfer) e.dataTransfer.dropEffect = "move";
            if (dropTargetId() !== node.NotebookId) setDropTargetId(node.NotebookId);
          }
        }}
        onDragLeave={() => { if (dropTargetId() === node.NotebookId) setDropTargetId(null); }}
        onDrop={(e) => {
          e.preventDefault();
          e.stopPropagation();
          const d = draggingId();
          setDropTargetId(null);
          setDraggingId(null);
          if (d && d !== node.NotebookId) void actions.reorderNotebook(d, node.NotebookId);
        }}
      >
        <button
          class="flex h-7 w-5 items-center justify-center text-subtle"
          onClick={() => hasChildren() && props.onToggle(node.NotebookId)}
        >
          <Show when={hasChildren()}>
            <ChevronRight
              size={14}
              class={`transition-transform ${isOpen() ? "rotate-90" : ""}`}
            />
          </Show>
        </button>

        <Show
          when={!renaming()}
          fallback={
            <input
              class="input h-7 flex-1 text-sm"
              value={title()}
              autofocus
              onInput={(e) => setTitle(e.currentTarget.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") submitRename();
                if (e.key === "Escape") setRenaming(false);
              }}
              onBlur={submitRename}
            />
          }
        >
          <button
            class={`flex min-w-0 flex-1 items-center gap-2 py-1.5 text-left text-sm
              ${isActive() ? "font-medium text-brand-700" : "text-fg"}`}
            onClick={() => {
              void actions.selectNotebook(node.NotebookId);
              if (isMobile()) {
                actions.setMobilePane("list");
                actions.setNbDrawer(false);
              }
            }}
          >
            <FileText size={14} class="shrink-0 text-subtle" />
            <span class="truncate">{node.Title || "未命名笔记本"}</span>
            <Show when={node.NumberNotes}>
              <span class="ml-auto pr-1 text-xs text-subtle">{node.NumberNotes}</span>
            </Show>
          </button>

          <Dropdown
            align="right"
            width="190px"
            trigger={({ toggle }) => (
              <button
                class="flex h-6 w-6 items-center justify-center rounded text-subtle opacity-0 transition-opacity hover:bg-black/10 group-hover:opacity-100 dark:hover:bg-white/10"
                onClick={(e) => { e.stopPropagation(); setPicker(null); toggle(); }}
              >
                <MoreHorizontal size={15} />
              </button>
            )}
          >
            {(close) => {
              const closeAll = () => { setPicker(null); close(); };
              return (
                <Show
                  when={picker() === null}
                  fallback={
                    <>
                      <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); setPicker(null); }}
                        class="flex w-full items-center gap-1.5 px-3 py-2 text-left text-xs font-medium text-subtle transition-colors hover:bg-black/5 dark:hover:bg-white/5"
                      >
                        <ChevronLeft size={13} />
                        移动到
                      </button>
                      <MenuDivider />
                      <div class="max-h-60 overflow-y-auto">
                        <Show when={node.ParentNotebookId}>
                          <MenuItem
                            icon={<CornerLeftUp size={14} />}
                            onClick={() => { closeAll(); void actions.moveNotebook(node.NotebookId, ""); }}
                          >
                            移到顶层
                          </MenuItem>
                          <MenuDivider />
                        </Show>
                        <For each={moveTargets()}>
                          {(nb) => (
                            <MenuItem onClick={() => { closeAll(); void actions.moveNotebook(node.NotebookId, nb.NotebookId); }}>
                              {nb.Title || "未命名"}
                            </MenuItem>
                          )}
                        </For>
                        <Show when={!moveTargets().length && !node.ParentNotebookId}>
                          <div class="px-3 py-2 text-xs text-subtle">没有可移动到的目标</div>
                        </Show>
                      </div>
                    </>
                  }
                >
                  <MenuItem icon={<Pencil size={14} />} onClick={() => { closeAll(); setTitle(node.Title); setRenaming(true); }}>
                    重命名
                  </MenuItem>
                  <MenuItem icon={<FolderPlus size={14} />} onClick={() => { closeAll(); startAddChild(); }}>
                    添加子笔记本
                  </MenuItem>
                  <SubmenuItem icon={<FolderInput size={14} />} label="移动到" onClick={() => setPicker("move")} />
                  <MenuDivider />
                  <MenuItem
                    icon={<Trash2 size={14} />}
                    danger
                    onClick={() => {
                      closeAll();
                      if (confirm(`确定删除笔记本「${node.Title}」？`)) void actions.deleteNotebook(node.NotebookId);
                    }}
                  >
                    删除
                  </MenuItem>
                </Show>
              );
            }}
          </Dropdown>
        </Show>
      </div>

      {/* 行内新建子笔记本 */}
      <Show when={addingChild()}>
        <div class="py-1 pr-2" style={{ "padding-left": `${(node.depth + 1) * 14 + 4}px` }}>
          <input
            class="input h-7 text-sm"
            placeholder="子笔记本名称，回车确认"
            value={childTitle()}
            autofocus
            onInput={(e) => setChildTitle(e.currentTarget.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") submitChild();
              if (e.key === "Escape") { setAddingChild(false); setChildTitle(""); }
            }}
            onBlur={submitChild}
          />
        </div>
      </Show>

      <Show when={hasChildren() && isOpen()}>
        <For each={node.children}>
          {(child) => <NotebookItem node={child} expanded={props.expanded} onToggle={props.onToggle} />}
        </For>
      </Show>
    </div>
  );
}

/** 二级菜单入口项（点开后切换到目标选择列表）。 */
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

function EmptyHint(props: { text: string }) {
  return <div class="px-4 py-6 text-center text-sm text-subtle">{props.text}</div>;
}
