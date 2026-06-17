import { createMemo, createSignal, onCleanup, onMount, createEffect, Show, For } from "solid-js";
import { EditorView, keymap, placeholder } from "@codemirror/view";
import { EditorState, EditorSelection, Compartment } from "@codemirror/state";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { markdown, markdownLanguage } from "@codemirror/lang-markdown";
import { languages } from "@codemirror/language-data";
import { syntaxHighlighting, defaultHighlightStyle, HighlightStyle } from "@codemirror/language";
import { tags as t } from "@lezer/highlight";
import {
  Eye,
  Columns2,
  Pencil,
  Image as ImageIcon,
  Bold,
  Italic,
  Strikethrough,
  Heading1,
  Heading2,
  Heading3,
  List,
  ListOrdered,
  ListTree,
  Quote,
  Code,
  Code2,
  Link2,
  Table,
  Minus,
} from "lucide-solid";
import { md, renderMermaid, decorateCodeBlocks } from "../../lib/markdown";
import { isDark } from "../../lib/theme";
import { isMobile } from "../../lib/responsive";
import { Dropdown } from "../ui/Dropdown";
import { ImagePickerModal } from "../album/ImagePickerModal";
import { fileApi } from "../../api/endpoints";
import { getImageBed, uploadToBed } from "../../lib/imageBed";
import { pushToast } from "../../state/toast";

type Mode = "split" | "edit" | "preview";

interface TocItem {
  id: string;
  text: string;
  level: number;
}

interface MarkdownEditorProps {
  content: string;
  noteId: string;
  editable: boolean;
  onChange: (md: string) => void;
}

// 由标题文本生成 URL 友好的锚点 id（保留中文，其它非词字符折成连字符）。
function slugify(text: string): string {
  return (
    text
      .toLowerCase()
      .trim()
      .replace(/[^\w一-鿿]+/g, "-")
      .replace(/^-+|-+$/g, "") || "h"
  );
}

const mdHighlight = HighlightStyle.define([
  // markdown 结构
  { tag: t.heading, fontWeight: "700", color: "rgb(var(--c-fg))" },
  { tag: t.strong, fontWeight: "700" },
  { tag: t.emphasis, fontStyle: "italic" },
  { tag: t.link, color: "rgb(var(--c-accent))" },
  { tag: t.monospace, fontFamily: "var(--font-mono, monospace)" },
  { tag: [t.quote], color: "rgb(var(--c-muted))" },
  { tag: [t.list], color: "rgb(var(--c-accent))" },
  // 围栏代码块内嵌语言 token（颜色用 CSS 变量，随明暗主题切换；与预览 Prism 配色一致）
  { tag: [t.comment, t.lineComment, t.blockComment, t.docComment], color: "var(--cm-comment)", fontStyle: "italic" },
  {
    tag: [t.keyword, t.controlKeyword, t.operatorKeyword, t.definitionKeyword, t.moduleKeyword, t.modifier, t.self],
    color: "var(--cm-keyword)",
  },
  { tag: [t.string, t.special(t.string), t.character], color: "var(--cm-string)" },
  { tag: [t.number, t.integer, t.float, t.bool, t.atom, t.null], color: "var(--cm-number)" },
  { tag: [t.function(t.variableName), t.function(t.propertyName)], color: "var(--cm-function)" },
  { tag: [t.typeName, t.className, t.namespace, t.constant(t.variableName)], color: "var(--cm-class)" },
  { tag: [t.propertyName, t.attributeName, t.tagName, t.labelName], color: "var(--cm-tag)" },
  { tag: [t.variableName, t.regexp, t.escape], color: "var(--cm-variable)" },
  {
    tag: [t.operator, t.punctuation, t.bracket, t.angleBracket, t.derefOperator, t.separator],
    color: "var(--cm-punct)",
  },
]);

const cmTheme = EditorView.theme({
  "&": { height: "100%", backgroundColor: "transparent", color: "rgb(var(--c-fg))" },
  ".cm-scroller": {
    fontFamily: "var(--font-mono, ui-monospace, monospace)",
    fontSize: "14px",
    lineHeight: "1.7",
    padding: "12px 20px",
  },
  "&.cm-focused": { outline: "none" },
  ".cm-content": { caretColor: "rgb(var(--c-accent))" },
  ".cm-cursor": { borderLeftColor: "rgb(var(--c-accent))" },
  ".cm-activeLine": { backgroundColor: "rgb(var(--c-fg) / 0.03)" },
  ".cm-selectionBackground, ::selection": { backgroundColor: "rgb(var(--c-accent) / 0.18)" },
  ".cm-placeholder": { color: "rgb(var(--c-subtle))" },
});

// 从文件名/MIME 推断带点的小写扩展名（默认 .png）。
function extOf(file: File): string {
  const m = /\.([a-z0-9]+)$/i.exec(file.name || "");
  if (m) return "." + m[1].toLowerCase();
  const sub = (file.type || "").split("/")[1];
  return sub ? "." + sub.toLowerCase() : ".png";
}

// 剪贴板粘贴的图片没有文件名 → 合成一个（不依赖 crypto，浏览器安全）。
function synthName(file: File): string {
  const rand = Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
  return `image-${rand}${extOf(file)}`;
}

export function MarkdownEditor(props: MarkdownEditorProps) {
  let host!: HTMLDivElement;
  let previewEl: HTMLDivElement | undefined;
  let view: EditorView | undefined;
  let applying = false; // 程序化替换文档时置真，避免触发 onChange
  const editableComp = new Compartment();
  const [mode, setMode] = createSignal<Mode>(isMobile() ? "edit" : "split");
  const [showPicker, setShowPicker] = createSignal(false);
  const [toc, setToc] = createSignal<TocItem[]>([]);

  const previewHtml = createMemo(() => md.render(props.content || ""));

  // ----- 图片插入 / 粘贴拖拽上传 -----
  const insertAtCursor = (text: string) => {
    if (!view) return;
    view.dispatch(view.state.replaceSelection(text));
    view.focus();
  };
  // name = 目标对象文件名（保留原名）；粘贴用合成名，拖拽/选文件用原名。
  const uploadAndInsert = async (file: File, name: string) => {
    if (!view) return;
    pushToast("上传图片中…", "info");
    try {
      const bed = await getImageBed();
      if (bed.imageBedType === "s3") {
        const url = await uploadToBed(bed, name, file);
        insertAtCursor(`![](${url})`);
        return;
      }
      // 本地存储
      const re = await fileApi.pasteImage(props.noteId, file);
      if (re?.Id) insertAtCursor(`![](${fileApi.imageUrl(re.Id)})`);
      else pushToast("上传失败", "error");
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "上传失败", "error");
    }
  };

  // ----- Markdown 格式化工具 -----
  // 用环绕标记包裹选区（无选区则插入占位符并选中，便于直接覆写）。支持多光标。
  const wrap = (before: string, after: string, placeholder: string) => {
    if (!view) return;
    const { state } = view;
    view.dispatch(
      state.changeByRange((range) => {
        const inner = state.sliceDoc(range.from, range.to) || placeholder;
        const from = range.from + before.length;
        return {
          changes: { from: range.from, to: range.to, insert: before + inner + after },
          range: EditorSelection.range(from, from + inner.length),
        };
      })
    );
    view.focus();
  };

  // 切换当前行标题级别：已是该级别则去掉，否则替换任意现有标题标记。
  const setHeading = (level: number) => {
    if (!view) return;
    const { state } = view;
    const line = state.doc.lineAt(state.selection.main.from);
    const marker = "#".repeat(level) + " ";
    const body = line.text.replace(/^#{1,6}\s+/, "");
    const insert = line.text.startsWith(marker) ? body : marker + body;
    view.dispatch({ changes: { from: line.from, to: line.to, insert }, scrollIntoView: true });
    view.focus();
  };

  // 行前缀（列表/引用）切换：选区各行全部已带前缀则移除，否则补齐。
  const toggleLinePrefix = (prefix: string, re: RegExp) => {
    if (!view) return;
    const { state } = view;
    const sel = state.selection.main;
    const first = state.doc.lineAt(sel.from).number;
    const last = state.doc.lineAt(sel.to).number;
    let all = true;
    for (let n = first; n <= last; n++) {
      const text = state.doc.line(n).text;
      if (text.trim() && !re.test(text)) {
        all = false;
        break;
      }
    }
    const changes: { from: number; to?: number; insert: string }[] = [];
    for (let n = first; n <= last; n++) {
      const line = state.doc.line(n);
      if (all) {
        const m = line.text.match(re);
        if (m) changes.push({ from: line.from, to: line.from + m[0].length, insert: "" });
      } else if (!re.test(line.text)) {
        changes.push({ from: line.from, insert: prefix });
      }
    }
    if (changes.length) view.dispatch({ changes, scrollIntoView: true });
    view.focus();
  };

  // 有序列表：逐行重新编号；全部已编号则取消。
  const orderedList = () => {
    if (!view) return;
    const { state } = view;
    const sel = state.selection.main;
    const first = state.doc.lineAt(sel.from).number;
    const last = state.doc.lineAt(sel.to).number;
    const re = /^\d+\.\s+/;
    let all = true;
    for (let n = first; n <= last; n++) {
      const text = state.doc.line(n).text;
      if (text.trim() && !re.test(text)) {
        all = false;
        break;
      }
    }
    const changes: { from: number; to?: number; insert: string }[] = [];
    let idx = 1;
    for (let n = first; n <= last; n++) {
      const line = state.doc.line(n);
      if (all) {
        const m = line.text.match(re);
        if (m) changes.push({ from: line.from, to: line.from + m[0].length, insert: "" });
      } else if (!re.test(line.text)) {
        changes.push({ from: line.from, insert: `${idx++}. ` });
      }
    }
    if (changes.length) view.dispatch({ changes, scrollIntoView: true });
    view.focus();
  };

  // 在行边界插入块级文本（表格/分割线等）。
  // 前导：光标前有内容→补空行分隔（块级元素需要空行才被 Markdown 正确解析）；
  // 行首但上一行非空→补一个换行。统一以单个换行收尾，光标落在块正下方的空行 ——
  // 不再像以前那样平白多出一两个空行。
  const insertBlock = (text: string, cursorOffset?: number) => {
    if (!view) return;
    const { state } = view;
    const at = state.selection.main.from;
    const line = state.doc.lineAt(at);
    const before = line.text.slice(0, at - line.from);
    let lead = "";
    if (before.trim()) {
      lead = "\n\n";
    } else if (line.number > 1 && state.doc.line(line.number - 1).text.trim()) {
      lead = "\n";
    }
    const body = text.endsWith("\n") ? text : text + "\n";
    const insert = lead + body;
    const pos = cursorOffset != null ? at + lead.length + cursorOffset : at + insert.length;
    view.dispatch({
      changes: { from: at, insert },
      selection: EditorSelection.cursor(pos),
      scrollIntoView: true,
    });
    view.focus();
  };

  const insertCodeBlock = () => {
    if (!view) return;
    const { state } = view;
    const range = state.selection.main;
    const selected = state.sliceDoc(range.from, range.to);
    const line = state.doc.lineAt(range.from);
    const lead = range.from === line.from ? "" : "\n";
    const insert = `${lead}\`\`\`\n${selected}\n\`\`\`\n`;
    view.dispatch({
      changes: { from: range.from, to: range.to, insert },
      // 光标停在开头 ``` 之后，便于直接输入语言名
      selection: EditorSelection.cursor(range.from + lead.length + 3),
      scrollIntoView: true,
    });
    view.focus();
  };

  const insertLink = () => {
    const url = window.prompt("链接地址", "https://");
    if (url === null) return;
    wrap("[", `](${url})`, "链接文字");
  };

  const insertTable = () =>
    insertBlock("| 列1 | 列2 |\n| --- | --- |\n| 单元格 | 单元格 |");
  const insertHr = () => insertBlock("---");

  // ----- 源行锚点同步 -----
  // anchors: 预览中带 data-line 的块，记录 { line(0基), top(相对预览滚动内容顶部) }
  let anchors: { line: number; top: number }[] = [];
  const buildAnchors = () => {
    if (!previewEl) return;
    const base = previewEl.getBoundingClientRect().top - previewEl.scrollTop;
    const list: { line: number; top: number }[] = [];
    previewEl.querySelectorAll<HTMLElement>("[data-line]").forEach((el) => {
      const line = Number(el.getAttribute("data-line"));
      if (!Number.isNaN(line)) list.push({ line, top: el.getBoundingClientRect().top - base });
    });
    list.sort((a, b) => a.line - b.line);
    anchors = list;
  };

  // 由源行插值出预览滚动位置
  const lineToTop = (line0: number): number => {
    const a = anchors;
    if (!a.length) return 0;
    if (line0 <= a[0].line) return a[0].top;
    for (let i = 0; i < a.length - 1; i++) {
      if (line0 < a[i + 1].line) {
        const span = a[i + 1].line - a[i].line || 1;
        const frac = (line0 - a[i].line) / span;
        return a[i].top + frac * (a[i + 1].top - a[i].top);
      }
    }
    return a[a.length - 1].top;
  };
  // 由预览滚动位置插值出源行
  const topToLine = (top: number): number => {
    const a = anchors;
    if (!a.length) return 0;
    if (top <= a[0].top) return a[0].line;
    for (let i = 0; i < a.length - 1; i++) {
      if (top < a[i + 1].top) {
        const span = a[i + 1].top - a[i].top || 1;
        const frac = (top - a[i].top) / span;
        return a[i].line + frac * (a[i + 1].line - a[i].line);
      }
    }
    return a[a.length - 1].line;
  };

  let lock = false;
  const release = () => requestAnimationFrame(() => (lock = false));
  const canSync = () => !lock && mode() === "split" && props.editable && view && previewEl && anchors.length;

  const onEditorScroll = () => {
    if (!canSync() || !view || !previewEl) return;
    const block = view.lineBlockAtHeight(view.scrollDOM.scrollTop);
    const line0 = view.state.doc.lineAt(block.from).number - 1;
    lock = true;
    previewEl.scrollTop = lineToTop(line0);
    release();
  };
  const onPreviewScroll = () => {
    if (!canSync() || !view || !previewEl) return;
    const line0 = topToLine(previewEl.scrollTop);
    const lineNum = Math.min(Math.max(Math.round(line0) + 1, 1), view.state.doc.lines);
    const block = view.lineBlockAt(view.state.doc.line(lineNum).from);
    lock = true;
    view.scrollDOM.scrollTop = block.top;
    release();
  };

  const scheduleRebuild = () => requestAnimationFrame(buildAnchors);

  // ----- 目录（TOC）-----
  // 渲染后扫描预览区标题，补 id 并生成目录项；点击滚动到对应标题。
  const buildToc = () => {
    if (!previewEl) return;
    const items: TocItem[] = [];
    const seen = new Set<string>();
    previewEl.querySelectorAll<HTMLElement>("h1, h2, h3, h4, h5, h6").forEach((el) => {
      const text = (el.textContent || "").trim();
      if (!text) return;
      let id = el.id;
      if (!id) {
        const base = slugify(text);
        id = base;
        let k = 1;
        while (seen.has(id)) id = `${base}-${k++}`;
        el.id = id;
      }
      seen.add(id);
      items.push({ id, text, level: Number(el.tagName.charAt(1)) });
    });
    setToc(items);
  };

  const scrollToHeading = (id: string) => {
    if (!previewEl) return;
    const el = previewEl.querySelector<HTMLElement>(`#${CSS.escape(id)}`);
    if (!el) return;
    previewEl.scrollTop += el.getBoundingClientRect().top - previewEl.getBoundingClientRect().top - 8;
  };

  onMount(() => {
    view = new EditorView({
      parent: host,
      state: EditorState.create({
        doc: props.content || "",
        extensions: [
          history(),
          keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
          markdown({ base: markdownLanguage, codeLanguages: languages }),
          EditorView.lineWrapping,
          syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
          syntaxHighlighting(mdHighlight),
          placeholder("使用 Markdown 书写…"),
          cmTheme,
          editableComp.of(EditorView.editable.of(props.editable)),
          EditorView.updateListener.of((u) => {
            if (u.docChanged && !applying) props.onChange(u.state.doc.toString());
          }),
          // 粘贴/拖拽图片 → 上传并在光标处插入 Markdown
          EditorView.domEventHandlers({
            paste: (event) => {
              const items = event.clipboardData?.items;
              if (!items) return false;
              for (const it of items) {
                if (it.kind === "file" && it.type.startsWith("image/")) {
                  const file = it.getAsFile();
                  if (file) {
                    event.preventDefault();
                    void uploadAndInsert(file, synthName(file));
                    return true;
                  }
                }
              }
              return false;
            },
            drop: (event) => {
              const files = Array.from(event.dataTransfer?.files ?? []).filter((f) =>
                f.type.startsWith("image/")
              );
              if (!files.length) return false;
              event.preventDefault();
              files.forEach((f) => void uploadAndInsert(f, f.name || synthName(f)));
              return true;
            },
          }),
        ],
      }),
    });
    view.scrollDOM.addEventListener("scroll", onEditorScroll, { passive: true });
    previewEl?.addEventListener("scroll", onPreviewScroll, { passive: true });
    window.addEventListener("resize", scheduleRebuild);
    scheduleRebuild();
  });

  // 内容/模式变化后重建锚点（DOM 更新后于下一帧测量）
  createEffect(() => {
    previewHtml();
    mode();
    isDark();
    scheduleRebuild();
    // 渲染后处理：注入复制按钮 + mermaid（图高度变化后再重测锚点）
    requestAnimationFrame(() => {
      if (!previewEl) return;
      decorateCodeBlocks(previewEl);
      buildToc();
      void renderMermaid(previewEl, isDark()).then(scheduleRebuild);
    });
  });

  // 外部内容变化（切换笔记 / 恢复历史版本）→ 整篇替换；
  // 用 applying 抑制由此引发的 onChange，避免误标脏。
  createEffect(() => {
    const incoming = props.content || "";
    if (!view || incoming === view.state.doc.toString()) return;
    applying = true;
    view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: incoming } });
    applying = false;
    scheduleRebuild();
  });

  // 只读/编辑切换
  createEffect(() => {
    view?.dispatch({ effects: editableComp.reconfigure(EditorView.editable.of(props.editable)) });
  });

  onCleanup(() => {
    view?.scrollDOM.removeEventListener("scroll", onEditorScroll);
    previewEl?.removeEventListener("scroll", onPreviewScroll);
    window.removeEventListener("resize", scheduleRebuild);
    view?.destroy();
  });

  const effectiveMode = (): Mode => (props.editable ? mode() : "preview");

  return (
    <div class="flex h-full flex-col">
      {/* 工具栏：格式化（左）+ 配图/模式（右） */}
      <Show when={props.editable}>
        <div class="flex items-center gap-1 border-b border-border px-2 py-1.5 sm:px-3">
          {/* 格式化按钮组：窄屏横向滚动，不再折行。纯预览时无操作对象故隐藏。 */}
          <div class="flex min-w-0 flex-1 items-center gap-0.5 overflow-x-auto no-scrollbar [&>*]:shrink-0">
          <Show when={effectiveMode() !== "preview"}>
            <ToolBtn title="标题 1" onClick={() => setHeading(1)}>
              <Heading1 size={16} />
            </ToolBtn>
            <ToolBtn title="标题 2" onClick={() => setHeading(2)}>
              <Heading2 size={16} />
            </ToolBtn>
            <ToolBtn title="标题 3" onClick={() => setHeading(3)}>
              <Heading3 size={16} />
            </ToolBtn>
            <Divider />
            <ToolBtn title="加粗" onClick={() => wrap("**", "**", "粗体")}>
              <Bold size={16} />
            </ToolBtn>
            <ToolBtn title="斜体" onClick={() => wrap("*", "*", "斜体")}>
              <Italic size={16} />
            </ToolBtn>
            <ToolBtn title="删除线" onClick={() => wrap("~~", "~~", "删除线")}>
              <Strikethrough size={16} />
            </ToolBtn>
            <ToolBtn title="行内代码" onClick={() => wrap("`", "`", "代码")}>
              <Code size={16} />
            </ToolBtn>
            <Divider />
            <ToolBtn title="无序列表" onClick={() => toggleLinePrefix("- ", /^[-*+]\s+/)}>
              <List size={16} />
            </ToolBtn>
            <ToolBtn title="有序列表" onClick={orderedList}>
              <ListOrdered size={16} />
            </ToolBtn>
            <ToolBtn title="引用" onClick={() => toggleLinePrefix("> ", /^>\s+/)}>
              <Quote size={16} />
            </ToolBtn>
            <ToolBtn title="代码块" onClick={insertCodeBlock}>
              <Code2 size={16} />
            </ToolBtn>
            <Divider />
            <ToolBtn title="链接" onClick={insertLink}>
              <Link2 size={16} />
            </ToolBtn>
            <ToolBtn title="表格" onClick={insertTable}>
              <Table size={16} />
            </ToolBtn>
            <ToolBtn title="分割线" onClick={insertHr}>
              <Minus size={16} />
            </ToolBtn>
          </Show>
          </div>

          <div class="flex shrink-0 items-center gap-0.5">
            <ToolBtn title="插入图片" onClick={() => setShowPicker(true)}>
              <ImageIcon size={16} />
            </ToolBtn>
            <Divider />
            <ToolBtn title="仅编辑" active={mode() === "edit"} onClick={() => setMode("edit")}>
              <Pencil size={16} />
            </ToolBtn>
            <Show when={!isMobile()}>
              <ToolBtn title="分栏" active={mode() === "split"} onClick={() => setMode("split")}>
                <Columns2 size={16} />
              </ToolBtn>
            </Show>
            <ToolBtn title="仅预览" active={mode() === "preview"} onClick={() => setMode("preview")}>
              <Eye size={16} />
            </ToolBtn>
          </div>
        </div>
      </Show>

      <div class="flex min-h-0 flex-1">
        {/* 编辑区 */}
        <div
          class="h-full overflow-hidden border-border"
          classList={{
            hidden: effectiveMode() === "preview",
            "w-1/2 border-r": effectiveMode() === "split",
            "w-full": effectiveMode() === "edit",
          }}
          ref={host}
        />
        {/* 预览区 */}
        <div
          class="relative h-full min-h-0"
          classList={{
            hidden: effectiveMode() === "edit",
            "w-1/2": effectiveMode() === "split",
            "w-full": effectiveMode() === "preview",
          }}
        >
          <div class="h-full overflow-y-auto" ref={previewEl}>
            <div class="prose prose-sm dark:prose-invert max-w-none px-6 py-5" innerHTML={previewHtml()} />
          </div>

          {/* 悬浮目录（TOC）按钮：仅在存在标题时显示 */}
          <Show when={toc().length > 0}>
            <div class="absolute right-3 top-3 z-10">
              <Dropdown
                align="right"
                width="240px"
                class="max-h-[60vh] overflow-y-auto"
                trigger={(api) => (
                  <button
                    type="button"
                    title="目录"
                    aria-label="目录"
                    onClick={api.toggle}
                    class="flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-surface/90 text-muted shadow-card backdrop-blur transition-colors hover:text-fg"
                    classList={{ "border-brand-500 text-brand-600": api.open }}
                  >
                    <ListTree size={16} />
                  </button>
                )}
              >
                {(close) => (
                  <For each={toc()}>
                    {(item) => (
                      <button
                        type="button"
                        title={item.text}
                        onClick={() => {
                          scrollToHeading(item.id);
                          close();
                        }}
                        class="block w-full truncate rounded px-2 py-1 text-left text-sm text-muted transition-colors hover:bg-black/5 hover:text-fg dark:hover:bg-white/5"
                        style={{ "padding-left": `${(item.level - 1) * 0.75 + 0.5}rem` }}
                      >
                        {item.text}
                      </button>
                    )}
                  </For>
                )}
              </Dropdown>
            </div>
          </Show>
        </div>
      </div>

      <ImagePickerModal
        open={showPicker()}
        onClose={() => setShowPicker(false)}
        onPick={(markdown) => insertAtCursor(markdown)}
      />
    </div>
  );
}

function ToolBtn(props: {
  title: string;
  active?: boolean;
  onClick: () => void;
  children: any;
}) {
  return (
    <button
      type="button"
      title={props.title}
      onClick={props.onClick}
      class={`flex h-8 w-8 items-center justify-center rounded-md transition-colors
        ${props.active ? "bg-brand-500/15 text-brand-600" : "text-muted hover:bg-black/5 hover:text-fg dark:hover:bg-white/5"}`}
    >
      {props.children}
    </button>
  );
}

function Divider() {
  return <div class="mx-1 h-5 w-px bg-border" />;
}
