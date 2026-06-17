import { createStore } from "solid-js/store";
import { batch } from "solid-js";
import { ApiError } from "../api/client";
import { notebookApi, noteApi, bootstrapApi } from "../api/endpoints";
import { pushToast } from "./toast";
import { saveLastView, loadLastView } from "../lib/lastView";
import { autoSaveMs } from "../lib/prefs";
import type { Note, NoteAndContent, Notebook, User } from "../api/types";

export type SortKey =
  | "updatedDesc"
  | "updatedAsc"
  | "createdDesc"
  | "createdAsc"
  | "titleAsc"
  | "titleDesc";
export type ViewMode = "snippet" | "list";

export type NotebookNode = Notebook & { children: NotebookNode[]; depth: number };

interface AppState {
  user: Partial<User> | null;
  notebooks: Notebook[];
  currentNotebookId: string;
  notes: Note[];
  currentNoteId: string;
  currentNote: NoteAndContent | null;
  activeTag: string;
  searchKey: string;
  trashView: boolean;
  sort: SortKey;
  viewMode: ViewMode;
  leftCollapsed: boolean;
  editing: boolean;
  immersive: boolean;
  // 移动端：当前可见单栏（列表/编辑器）+ 笔记本抽屉开关
  mobilePane: "list" | "editor";
  nbDrawerOpen: boolean;
  loadingNotebooks: boolean;
  loadingNotes: boolean;
  loadingNote: boolean;
  saving: boolean;
  dirty: boolean;
  ready: boolean;
  authExpired: boolean;
}

const [state, setState] = createStore<AppState>({
  user: null,
  notebooks: [],
  currentNotebookId: "",
  notes: [],
  currentNoteId: "",
  currentNote: null,
  activeTag: "",
  searchKey: "",
  trashView: false,
  sort: "updatedDesc",
  viewMode: "snippet",
  leftCollapsed: false,
  editing: true,
  immersive: false,
  mobilePane: "list",
  nbDrawerOpen: false,
  loadingNotebooks: false,
  loadingNotes: false,
  loadingNote: false,
  saving: false,
  dirty: false,
  ready: false,
  authExpired: false,
});

export { state as appState };

// ---------- 派生 ----------

/** getNotebooks 返回的是按 Subs 嵌套的树，拍平为扁平列表（子笔记本自带 ParentNotebookId）。 */
export function flattenNotebooks(nodes: Notebook[]): Notebook[] {
  const out: Notebook[] = [];
  const walk = (list: Notebook[]) => {
    for (const n of list) {
      out.push(n);
      if (n.Subs && n.Subs.length) walk(n.Subs);
    }
  };
  walk(nodes || []);
  return out;
}

/** 把扁平笔记本列表构建为树（按 ParentNotebookId + Seq） */
export function buildNotebookTree(notebooks: Notebook[]): NotebookNode[] {
  const map = new Map<string, NotebookNode>();
  notebooks.forEach((nb) => map.set(nb.NotebookId, { ...nb, children: [], depth: 0 }));
  const roots: NotebookNode[] = [];
  for (const node of map.values()) {
    const parent = node.ParentNotebookId ? map.get(node.ParentNotebookId) : undefined;
    if (parent) parent.children.push(node);
    else roots.push(node);
  }
  const sortRec = (nodes: NotebookNode[], depth: number) => {
    nodes.sort((a, b) => (a.Seq ?? 0) - (b.Seq ?? 0) || a.Title.localeCompare(b.Title));
    for (const n of nodes) {
      n.depth = depth;
      sortRec(n.children, depth + 1);
    }
  };
  sortRec(roots, 0);
  return roots;
}

export function sortNotes(notes: Note[], sort: SortKey): Note[] {
  const arr = notes.slice();
  const t = (s?: string) => (s ? new Date(s).getTime() : 0);
  arr.sort((a, b) => {
    switch (sort) {
      case "updatedAsc":
        return t(a.UpdatedTime) - t(b.UpdatedTime);
      case "updatedDesc":
        return t(b.UpdatedTime) - t(a.UpdatedTime);
      case "createdAsc":
        return t(a.CreatedTime) - t(b.CreatedTime);
      case "createdDesc":
        return t(b.CreatedTime) - t(a.CreatedTime);
      case "titleAsc":
        return (a.Title || "").localeCompare(b.Title || "");
      case "titleDesc":
        return (b.Title || "").localeCompare(a.Title || "");
    }
  });
  // 置顶
  return arr.sort((a, b) => Number(!!b.IsTop) - Number(!!a.IsTop));
}

/** 当前笔记本下所有标签（从已加载笔记派生） */
export function deriveTags(notes: Note[]): { tag: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const n of notes) {
    for (const tag of n.Tags ?? []) {
      if (!tag) continue;
      counts.set(tag, (counts.get(tag) ?? 0) + 1);
    }
  }
  return Array.from(counts, ([tag, count]) => ({ tag, count })).sort((a, b) =>
    a.tag.localeCompare(b.tag)
  );
}

function handleError(err: unknown, fallback: string) {
  if (err instanceof ApiError && err.isAuth) {
    setState("authExpired", true);
    return;
  }
  const msg = err instanceof ApiError ? err.message : fallback;
  pushToast(msg || fallback, "error");
}

// 调整某笔记本及其所有祖先的 NumberNotes。笔记数为子树聚合（own + 全后代），
// 故移动/增删笔记时需沿 ParentNotebookId 上溯同步整条链（delta 取 +1/-1）。
// 移动时对源链 -1、目的链 +1，公共祖先净抵为 0，各种父子关系皆正确。
function bumpNotebookCount(notebookId: string | undefined, delta: number) {
  if (!notebookId || !delta) return;
  const byId = new Map(state.notebooks.map((n) => [n.NotebookId, n]));
  const seen = new Set<string>();
  let id: string | undefined = notebookId;
  while (id && !seen.has(id)) {
    const cur: string = id;
    seen.add(cur);
    setState(
      "notebooks",
      (n) => n.NotebookId === cur,
      "NumberNotes",
      (c) => Math.max(0, (c ?? 0) + delta)
    );
    id = byId.get(cur)?.ParentNotebookId || undefined;
  }
}

// 从当前列表移除一条笔记并选中相邻一条（删除/恢复/彻底删除共用）。
async function dropNoteFromList(noteId: string) {
  const idx = state.notes.findIndex((n) => n.NoteId === noteId);
  setState("notes", (prev) => prev.filter((n) => n.NoteId !== noteId));
  if (state.currentNoteId === noteId) {
    const next = state.notes[idx] ?? state.notes[idx - 1];
    if (next) await actions.selectNote(next.NoteId);
    else
      batch(() => {
        setState("currentNoteId", "");
        setState("currentNote", null);
      });
  }
}

// ---------- 动作 ----------

let saveTimer: ReturnType<typeof setTimeout> | undefined;

export const actions = {
  async bootstrap() {
    // 先同步清掉可能残留的过期标记：若之前未登录访问过 /note，authExpired 会被
    // 置真且常驻 store；登录后 NotesPage 重新挂载时那个旧标记会让守卫 effect 立刻
    // 把人弹回登录页（表现为「登录后不跳转」）。在任何 await 之前清掉它。
    setState("authExpired", false);
    // 会话 cookie 为 HttpOnly，改用 GET /user/info 判定登录态
    const user = await bootstrapApi.fetchUserInfo();
    if (!user) {
      setState("authExpired", true);
      return;
    }
    setState("user", user);
    await actions.loadNotebooks();
    // 恢复上次浏览的笔记本/笔记；失效则回退到第一个笔记本。
    const live = (id: string) => state.notebooks.some((n) => n.NotebookId === id && !n.IsTrash);
    const saved = loadLastView(user.UserId ?? "");
    const first = state.notebooks.find((n) => !n.IsTrash)?.NotebookId;
    const targetNb = saved && live(saved.notebookId) ? saved.notebookId : first;
    if (targetNb) {
      const preferNote = saved && saved.notebookId === targetNb ? saved.noteId : "";
      await actions.selectNotebook(targetNb, preferNote);
    }
    setState("ready", true);
  },

  async loadNotebooks() {
    setState("loadingNotebooks", true);
    try {
      const list = (await notebookApi.list()) || [];
      // 后端返回 Subs 嵌套树，拍平后供树构建与 .find() 查找
      const flat = flattenNotebooks(Array.isArray(list) ? list : []);
      setState("notebooks", flat.filter((n) => !n.IsDeleted));
    } catch (err) {
      handleError(err, "加载笔记本失败");
    } finally {
      setState("loadingNotebooks", false);
    }
  },

  async selectNotebook(notebookId: string, preferNoteId = "") {
    batch(() => {
      setState("currentNotebookId", notebookId);
      setState("activeTag", "");
      setState("searchKey", "");
      setState("trashView", false);
    });
    await actions.loadNotes(notebookId, preferNoteId);
  },

  // 废纸篓视图：加载已删除（IsTrash）的笔记到列表（不经 loadNotes 的非删过滤）。
  async showTrash() {
    batch(() => {
      setState("trashView", true);
      setState("currentNotebookId", "");
      setState("activeTag", "");
      setState("searchKey", "");
    });
    setState("loadingNotes", true);
    try {
      const list = (await noteApi.trash()) || [];
      setState("notes", Array.isArray(list) ? list : []);
      if (state.notes.length) await actions.selectNote(state.notes[0].NoteId);
      else batch(() => {
        setState("currentNoteId", "");
        setState("currentNote", null);
      });
    } catch (err) {
      handleError(err, "加载废纸篓失败");
    } finally {
      setState("loadingNotes", false);
    }
  },

  async loadNotes(notebookId: string, preferNoteId = "") {
    setState("loadingNotes", true);
    try {
      const list = (await noteApi.list(notebookId)) || [];
      const notes = Array.isArray(list) ? list.filter((n) => !n.IsTrash) : [];
      setState("notes", notes);
      // 优先选中指定笔记（恢复上次状态）；否则选第一条
      const prefer = preferNoteId && notes.some((n) => n.NoteId === preferNoteId) ? preferNoteId : "";
      if (prefer) await actions.selectNote(prefer);
      else if (notes.length) await actions.selectNote(notes[0].NoteId);
      else {
        batch(() => {
          setState("currentNoteId", "");
          setState("currentNote", null);
        });
        saveLastView(state.user?.UserId ?? "", { notebookId, noteId: "" });
      }
    } catch (err) {
      handleError(err, "加载笔记失败");
    } finally {
      setState("loadingNotes", false);
    }
  },

  async selectNote(noteId: string) {
    if (state.dirty) await actions.saveNow();
    setState("currentNoteId", noteId);
    saveLastView(state.user?.UserId ?? "", { notebookId: state.currentNotebookId, noteId });
    setState("loadingNote", true);
    try {
      const note = await noteApi.getAndContent(noteId);
      // getNoteAndContent 不返回 NoteId，需从请求补回
      setState("currentNote", { ...note, NoteId: noteId });
    } catch (err) {
      handleError(err, "加载笔记内容失败");
    } finally {
      setState("loadingNote", false);
    }
  },

  async createNote(isMarkdown: boolean) {
    const notebookId = state.currentNotebookId || state.notebooks[0]?.NotebookId;
    if (!notebookId) {
      pushToast("请先创建一个笔记本", "error");
      return;
    }
    try {
      const note = await noteApi.create({
        NotebookId: notebookId,
        Title: "",
        Content: "",
        IsMarkdown: isMarkdown,
      });
      if (note && note.NoteId) {
        setState("notes", (prev) => [note, ...prev]);
        bumpNotebookCount(notebookId, +1);
        setState("currentNoteId", note.NoteId);
        setState("currentNote", { ...note, Content: "" } as NoteAndContent);
        setState("editing", true);
      }
    } catch (err) {
      handleError(err, "新建笔记失败");
    }
  },

  /** 本地修改当前笔记字段，并安排自动保存 */
  patchCurrent(patch: Partial<NoteAndContent>) {
    if (!state.currentNote) return;
    setState("currentNote", (n) => (n ? { ...n, ...patch } : n));
    // 同步列表中的标题/摘要展示
    setState(
      "notes",
      (note) => note.NoteId === state.currentNoteId,
      (note) => ({ ...note, ...patch })
    );
    setState("dirty", true);
    if (saveTimer) clearTimeout(saveTimer);
    // 自动保存间隔为用户可配置项（lib/prefs，存 localStorage）。
    saveTimer = setTimeout(() => void actions.saveNow(), autoSaveMs());
  },

  async saveNow() {
    if (!state.currentNote || !state.dirty) return;
    if (saveTimer) {
      clearTimeout(saveTimer);
      saveTimer = undefined;
    }
    const note = state.currentNote;
    setState("saving", true);
    try {
      await noteApi.update({
        NoteId: note.NoteId,
        Title: note.Title ?? "",
        Content: note.Content ?? "",
        Abstract: makeAbstract(note),
        Tags: note.Tags ?? [],
      });
      setState("dirty", false);
    } catch (err) {
      handleError(err, "保存失败");
    } finally {
      setState("saving", false);
    }
  },

  async deleteNote(noteId: string) {
    const srcNotebookId = state.notes.find((n) => n.NoteId === noteId)?.NotebookId;
    try {
      await noteApi.delete([noteId]);
      const idx = state.notes.findIndex((n) => n.NoteId === noteId);
      setState("notes", (prev) => prev.filter((n) => n.NoteId !== noteId));
      bumpNotebookCount(srcNotebookId, -1);
      if (state.currentNoteId === noteId) {
        const next = state.notes[idx] ?? state.notes[idx - 1];
        if (next) await actions.selectNote(next.NoteId);
        else
          batch(() => {
            setState("currentNoteId", "");
            setState("currentNote", null);
          });
      }
    } catch (err) {
      handleError(err, "删除失败");
    }
  },

  // 废纸篓：恢复 / 彻底删除
  async restoreNote(noteId: string) {
    const dstNotebookId = state.notes.find((n) => n.NoteId === noteId)?.NotebookId;
    try {
      await noteApi.restore([noteId]);
      await dropNoteFromList(noteId);
      // 恢复出废纸篓后重新计入其笔记本（彻底删除则无需，本就不计入）
      bumpNotebookCount(dstNotebookId, +1);
      pushToast("已恢复", "success");
    } catch (err) {
      handleError(err, "恢复失败");
    }
  },

  async purgeNote(noteId: string) {
    try {
      await noteApi.deleteTrash([noteId]);
      await dropNoteFromList(noteId);
    } catch (err) {
      handleError(err, "彻底删除失败");
    }
  },

  async moveNote(noteId: string, notebookId: string) {
    if (notebookId === state.currentNotebookId) return;
    // 源笔记本以笔记自身的 NotebookId 为准（搜索/跨本场景比 currentNotebookId 可靠）
    const srcNotebookId = state.notes.find((n) => n.NoteId === noteId)?.NotebookId;
    try {
      await noteApi.move([noteId], notebookId);
      // 从当前列表移除（已移动到别的笔记本）
      const idx = state.notes.findIndex((n) => n.NoteId === noteId);
      setState("notes", (prev) => prev.filter((n) => n.NoteId !== noteId));
      // 同步源/目的笔记本（及各自祖先）的笔记数
      bumpNotebookCount(srcNotebookId, -1);
      bumpNotebookCount(notebookId, +1);
      if (state.currentNoteId === noteId) {
        const next = state.notes[idx] ?? state.notes[idx - 1];
        if (next) await actions.selectNote(next.NoteId);
        else
          batch(() => {
            setState("currentNoteId", "");
            setState("currentNote", null);
          });
      }
      pushToast("已移动笔记", "success");
    } catch (err) {
      handleError(err, "移动失败");
    }
  },

  async copyNote(noteId: string, notebookId: string) {
    // 复制目标必为其它笔记本（菜单已禁用当前笔记本），故不改动当前列表
    try {
      await noteApi.copy([noteId], notebookId);
      bumpNotebookCount(notebookId, +1);
      pushToast("已复制笔记", "success");
    } catch (err) {
      handleError(err, "复制失败");
    }
  },

  // 设为/取消博客、博客置顶（isBlog=false 时 isTop 无意义）
  async setNoteBlog(noteId: string, isBlog: boolean, isTop = false) {
    try {
      await noteApi.setBlog([noteId], isBlog, isTop);
      setState("notes", (n) => n.NoteId === noteId, (n) => ({ ...n, IsBlog: isBlog, IsTop: isTop }));
      if (state.currentNoteId === noteId) {
        setState("currentNote", (c) => (c ? { ...c, IsBlog: isBlog, IsTop: isTop } : c));
      }
      pushToast(
        isBlog ? (isTop ? "已置顶到博客" : "已设为博客") : "已取消公开",
        "success"
      );
    } catch (err) {
      handleError(err, "操作失败");
    }
  },

  // 更新某篇博客的元数据（自定义链接 / 摘要 / 封面图）。返回规范化后的 UrlTitle
  // （可能因去重而带 -2 后缀）。抛错交由调用方处理。
  async updateBlogMeta(noteId: string, meta: { UrlTitle?: string; Desc?: string; ImgSrc?: string }): Promise<string> {
    const re = await noteApi.updateBlogMeta(noteId, meta);
    const urlTitle = (re.Item as { UrlTitle?: string } | undefined)?.UrlTitle ?? meta.UrlTitle ?? "";
    setState("notes", (n) => n.NoteId === noteId, (n) => ({
      ...n,
      UrlTitle: urlTitle,
      Desc: meta.Desc ?? n.Desc,
      ImgSrc: meta.ImgSrc ?? n.ImgSrc,
    }));
    if (state.currentNoteId === noteId) {
      setState("currentNote", (c) => (c ? { ...c, UrlTitle: urlTitle, Desc: meta.Desc ?? c.Desc, ImgSrc: meta.ImgSrc ?? c.ImgSrc } : c));
    }
    return urlTitle;
  },
  async createNotebook(title: string, parentNotebookId = "") {
    try {
      const nb = await notebookApi.add(title, parentNotebookId);
      if (nb && typeof nb === "object") {
        setState("notebooks", (prev) => [...prev, nb]);
        await actions.selectNotebook(nb.NotebookId);
      }
    } catch (err) {
      handleError(err, "新建笔记本失败");
    }
  },

  async renameNotebook(notebookId: string, title: string) {
    try {
      await notebookApi.updateTitle(notebookId, title);
      setState("notebooks", (n) => n.NotebookId === notebookId, "Title", title);
    } catch (err) {
      handleError(err, "重命名失败");
    }
  },

  async deleteNotebook(notebookId: string) {
    try {
      await notebookApi.delete(notebookId);
      setState("notebooks", (prev) => prev.filter((n) => n.NotebookId !== notebookId));
      if (state.currentNotebookId === notebookId) {
        const first = state.notebooks.find((n) => n.NotebookId !== notebookId);
        if (first) await actions.selectNotebook(first.NotebookId);
      }
    } catch (err) {
      handleError(err, "删除笔记本失败");
    }
  },

  // 移动笔记本到另一个笔记本下（parentNotebookId 为空=移到顶层）。改父后重新拉取
  // 列表，刷新树结构与各级聚合的 NumberNotes。
  async moveNotebook(notebookId: string, parentNotebookId: string) {
    try {
      const ok = await notebookApi.drag({ curNotebookId: notebookId, parentNotebookId, siblings: [] });
      if (ok) await actions.loadNotebooks();
      else handleError(new Error("移动失败"), "移动笔记本失败");
    } catch (err) {
      handleError(err, "移动笔记本失败");
    }
  },

  // 拖拽：把 dragged 放到 target 之后、成为 target 的同级（同父则纯重排，跨父则连带改父）。
  async reorderNotebook(draggedId: string, targetId: string) {
    if (draggedId === targetId) return;
    const byId = new Map(state.notebooks.map((n) => [n.NotebookId, n]));
    const target = byId.get(targetId);
    if (!byId.get(draggedId) || !target) return;
    // 防成环：target 不能是 dragged 的后代
    const isDescendantOfDragged = (id: string) => {
      let p = byId.get(id)?.ParentNotebookId || "";
      while (p) {
        if (p === draggedId) return true;
        p = byId.get(p)?.ParentNotebookId || "";
      }
      return false;
    };
    if (isDescendantOfDragged(targetId)) return;
    const newParent = target.ParentNotebookId || "";
    const sibs = state.notebooks
      .filter((n) => (n.ParentNotebookId || "") === newParent && n.NotebookId !== draggedId && !n.IsTrash)
      .sort((a, b) => (a.Seq ?? 0) - (b.Seq ?? 0))
      .map((n) => n.NotebookId);
    const ti = sibs.indexOf(targetId);
    sibs.splice(ti + 1, 0, draggedId); // 插到 target 之后
    try {
      await notebookApi.drag({ curNotebookId: draggedId, parentNotebookId: newParent, siblings: sibs });
      await actions.loadNotebooks();
    } catch (err) {
      handleError(err, "排序失败");
    }
  },

  async search(key: string) {
    setState("searchKey", key);
    if (!key.trim()) {
      if (state.currentNotebookId) await actions.loadNotes(state.currentNotebookId);
      return;
    }
    setState("trashView", false);
    setState("loadingNotes", true);
    try {
      const list = (await noteApi.search(key)) || [];
      setState("notes", Array.isArray(list) ? list : []);
      if (state.notes.length) await actions.selectNote(state.notes[0].NoteId);
    } catch (err) {
      handleError(err, "搜索失败");
    } finally {
      setState("loadingNotes", false);
    }
  },

  setActiveTag(tag: string) {
    setState("activeTag", state.activeTag === tag ? "" : tag);
  },
  setSort(sort: SortKey) {
    setState("sort", sort);
  },
  setViewMode(viewMode: ViewMode) {
    setState("viewMode", viewMode);
  },
  toggleLeft() {
    setState("leftCollapsed", (v) => !v);
  },
  // 移动端单栏 / 抽屉
  setMobilePane(pane: "list" | "editor") {
    setState("mobilePane", pane);
  },
  setNbDrawer(open: boolean) {
    setState("nbDrawerOpen", open);
  },
  toggleNbDrawer() {
    setState("nbDrawerOpen", (v) => !v);
  },
  setEditing(editing: boolean) {
    setState("editing", editing);
  },
  /** 局部更新当前用户信息（改名/头像后同步到 Header 等） */
  patchUser(patch: Partial<User>) {
    setState("user", (u) => (u ? { ...u, ...patch } : u));
  },
  toggleImmersive() {
    setState("immersive", (v) => !v);
  },
  setImmersive(immersive: boolean) {
    setState("immersive", immersive);
  },
  /** 上传/删除附件后局部同步当前笔记与列表项的附件数 */
  setAttachNum(n: number) {
    setState("currentNote", (cn) => (cn ? { ...cn, AttachNum: n } : cn));
    setState(
      "notes",
      (note) => note.NoteId === state.currentNoteId,
      "AttachNum",
      n
    );
  },
};

/** 从内容生成摘要（去 HTML/markdown 标记，截断） */
function makeAbstract(note: NoteAndContent): string {
  const raw = note.Content ?? "";
  const text = note.IsMarkdown
    ? raw.replace(/[#>*`_~\-]+/g, " ")
    : raw.replace(/<[^>]+>/g, " ");
  return text.replace(/\s+/g, " ").trim().slice(0, 100);
}
