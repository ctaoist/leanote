import { createSignal, onCleanup, onMount, createEffect, For, Show } from "solid-js";
import { Editor } from "@tiptap/core";
import StarterKit from "@tiptap/starter-kit";
import Underline from "@tiptap/extension-underline";
import Link from "@tiptap/extension-link";
import Placeholder from "@tiptap/extension-placeholder";
import {
  Bold,
  Italic,
  Underline as UnderlineIcon,
  Strikethrough,
  Heading1,
  Heading2,
  Heading3,
  List,
  ListOrdered,
  Quote,
  Code,
  Link2,
  Undo2,
  Redo2,
} from "lucide-solid";
import { CodeBlockPrism } from "./codeBlockPrism";
import { PRISM_LANGUAGES } from "../../lib/prism";

interface RichTextEditorProps {
  content: string;
  noteId: string;
  editable: boolean;
  onChange: (html: string) => void;
}

export function RichTextEditor(props: RichTextEditorProps) {
  let element!: HTMLDivElement;
  let editor: Editor | undefined;
  const [tick, setTick] = createSignal(0); // 触发工具栏状态刷新

  onMount(() => {
    editor = new Editor({
      element,
      extensions: [
        StarterKit.configure({ heading: { levels: [1, 2, 3] }, codeBlock: false }),
        CodeBlockPrism,
        Underline,
        Link.configure({ openOnClick: false, autolink: true }),
        Placeholder.configure({ placeholder: "开始书写…" }),
      ],
      content: props.content || "",
      editable: props.editable,
      onUpdate: ({ editor }) => props.onChange(editor.getHTML()),
      onTransaction: () => setTick((t) => t + 1),
      editorProps: {
        attributes: {
          class:
            "prose prose-sm dark:prose-invert max-w-none min-h-full focus:outline-none px-6 py-5",
        },
      },
    });
  });

  // 外部内容变化（切换笔记 / 恢复历史版本）→ 替换内容，不触发保存
  createEffect(() => {
    const incoming = props.content || "";
    if (editor && incoming !== editor.getHTML()) {
      editor.commands.setContent(incoming, { emitUpdate: false });
    }
  });
  createEffect(() => editor?.setEditable(props.editable));

  onCleanup(() => editor?.destroy());

  const cmd = (fn: (e: Editor) => void) => () => editor && fn(editor);
  const isActive = (name: string, attrs?: Record<string, unknown>) => {
    tick();
    return !!editor?.isActive(name, attrs);
  };
  // 当前代码块语言（随事务刷新）
  const codeLang = () => {
    tick();
    return (editor?.getAttributes("codeBlock").language as string) ?? "";
  };
  const setCodeLang = (value: string) =>
    editor?.chain().focus().updateAttributes("codeBlock", { language: value || null }).run();

  return (
    <div class="flex h-full flex-col">
      <Show when={props.editable}>
        <div class="flex flex-wrap items-center gap-0.5 border-b border-border px-3 py-1.5">
          <For each={headingButtons}>
            {(b) => (
              <ToolBtn
                title={b.title}
                active={isActive("heading", { level: b.level })}
                onClick={cmd((e) => e.chain().focus().toggleHeading({ level: b.level as 1 | 2 | 3 }).run())}
              >
                <b.icon size={16} />
              </ToolBtn>
            )}
          </For>
          <Divider />
          <ToolBtn title="加粗" active={isActive("bold")} onClick={cmd((e) => e.chain().focus().toggleBold().run())}>
            <Bold size={16} />
          </ToolBtn>
          <ToolBtn title="斜体" active={isActive("italic")} onClick={cmd((e) => e.chain().focus().toggleItalic().run())}>
            <Italic size={16} />
          </ToolBtn>
          <ToolBtn title="下划线" active={isActive("underline")} onClick={cmd((e) => e.chain().focus().toggleUnderline().run())}>
            <UnderlineIcon size={16} />
          </ToolBtn>
          <ToolBtn title="删除线" active={isActive("strike")} onClick={cmd((e) => e.chain().focus().toggleStrike().run())}>
            <Strikethrough size={16} />
          </ToolBtn>
          <Divider />
          <ToolBtn title="无序列表" active={isActive("bulletList")} onClick={cmd((e) => e.chain().focus().toggleBulletList().run())}>
            <List size={16} />
          </ToolBtn>
          <ToolBtn title="有序列表" active={isActive("orderedList")} onClick={cmd((e) => e.chain().focus().toggleOrderedList().run())}>
            <ListOrdered size={16} />
          </ToolBtn>
          <ToolBtn title="引用" active={isActive("blockquote")} onClick={cmd((e) => e.chain().focus().toggleBlockquote().run())}>
            <Quote size={16} />
          </ToolBtn>
          <ToolBtn title="代码块" active={isActive("codeBlock")} onClick={cmd((e) => e.chain().focus().toggleCodeBlock().run())}>
            <Code size={16} />
          </ToolBtn>
          <ToolBtn title="链接" active={isActive("link")} onClick={cmd((e) => setLink(e))}>
            <Link2 size={16} />
          </ToolBtn>
          <Divider />
          <ToolBtn title="撤销" onClick={cmd((e) => e.chain().focus().undo().run())}>
            <Undo2 size={16} />
          </ToolBtn>
          <ToolBtn title="重做" onClick={cmd((e) => e.chain().focus().redo().run())}>
            <Redo2 size={16} />
          </ToolBtn>

          {/* 光标在代码块内时：选择高亮语言 */}
          <Show when={isActive("codeBlock")}>
            <Divider />
            <select
              title="代码语言"
              class="h-8 rounded-md border border-border bg-surface px-2 text-xs text-fg
                focus:outline-none focus:ring-2 focus:ring-brand-500/30"
              value={codeLang()}
              onChange={(e) => setCodeLang(e.currentTarget.value)}
            >
              <For each={PRISM_LANGUAGES}>
                {(l) => <option value={l.value}>{l.label}</option>}
              </For>
            </select>
          </Show>
        </div>
      </Show>
      <div class="flex-1 overflow-y-auto" ref={element} />
    </div>
  );
}

const headingButtons = [
  { level: 1, icon: Heading1, title: "标题 1" },
  { level: 2, icon: Heading2, title: "标题 2" },
  { level: 3, icon: Heading3, title: "标题 3" },
] as const;

function setLink(editor: Editor) {
  const prev = editor.getAttributes("link").href as string | undefined;
  const url = window.prompt("链接地址", prev ?? "https://");
  if (url === null) return;
  if (url === "") {
    editor.chain().focus().extendMarkRange("link").unsetLink().run();
    return;
  }
  editor.chain().focus().extendMarkRange("link").setLink({ href: url }).run();
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
