// 富文本（TipTap）代码块语法高亮：扩展 StarterKit 的 CodeBlock，挂一个
// ProseMirror 插件，用共享 Prism 对代码块文本做 token 切分并以 inline 装饰
// 渲染成 `<span class="token keyword">…`。装饰 class 与 markdown 预览的 Prism
// 输出一致，因此直接命中 app.css 里 `.prose .token.*` 主题（明/暗自动切换），
// 无需额外样式，也不引入第二套高亮库（lowlight/highlight.js）。
import { findChildren } from "@tiptap/core";
import CodeBlock from "@tiptap/extension-code-block";
import { Plugin, PluginKey } from "@tiptap/pm/state";
import { Decoration, DecorationSet } from "@tiptap/pm/view";
import type { Node as ProseNode } from "@tiptap/pm/model";
import { Prism, normalizeLang } from "../../lib/prism";

// Prism.tokenize 的返回项：纯字符串，或带类型/别名/嵌套内容的 Token。
type PrismToken = {
  type: string;
  alias?: string | string[];
  content: string | PrismToken | (string | PrismToken)[];
};
type PrismNode = string | PrismToken;

interface Segment {
  length: number;
  classes: string[];
}

/** 递归把 Prism token 树拍平成「连续文本段 + 其 class 链」。 */
function flatten(nodes: PrismNode[], parent: string[], out: Segment[]): void {
  for (const node of nodes) {
    if (typeof node === "string") {
      out.push({ length: node.length, classes: parent });
      continue;
    }
    const aliases = node.alias
      ? Array.isArray(node.alias)
        ? node.alias
        : [node.alias]
      : [];
    const classes = [...parent, "token", node.type, ...aliases];
    if (Array.isArray(node.content)) {
      flatten(node.content, classes, out);
    } else if (typeof node.content === "string") {
      out.push({ length: node.content.length, classes });
    } else {
      flatten([node.content], classes, out);
    }
  }
}

/** 为文档内所有指定类型的代码块节点构建高亮装饰集合。 */
function getDecorations(doc: ProseNode, name: string): DecorationSet {
  const decorations: Decoration[] = [];
  findChildren(doc, (node) => node.type.name === name).forEach(({ node, pos }) => {
    const lang = normalizeLang(node.attrs.language as string | null);
    const grammar = lang ? Prism.languages[lang] : undefined;
    if (!grammar) return;

    const segments: Segment[] = [];
    flatten(Prism.tokenize(node.textContent, grammar) as PrismNode[], [], segments);

    // 代码块内容起点：节点位置 +1（进入 textblock 内部）。每字符占 1 个位置。
    let from = pos + 1;
    for (const seg of segments) {
      const to = from + seg.length;
      const cls = Array.from(new Set(seg.classes)).join(" ").trim();
      if (cls) decorations.push(Decoration.inline(from, to, { class: cls }));
      from = to;
    }
  });
  return DecorationSet.create(doc, decorations);
}

function prismPlugin(name: string): Plugin {
  const key = new PluginKey("codeBlockPrism");
  return new Plugin({
    key,
    state: {
      init: (_config, { doc }) => getDecorations(doc, name),
      // 文档变化（含改语言属性）时整体重算；否则随映射平移既有装饰。
      apply: (tr, deco) =>
        tr.docChanged ? getDecorations(tr.doc, name) : deco.map(tr.mapping, tr.doc),
    },
    props: {
      decorations(state) {
        return key.getState(state);
      },
    },
  });
}

/** 带 Prism 高亮的代码块扩展（节点名仍为 codeBlock，工具栏命令不变）。 */
export const CodeBlockPrism = CodeBlock.extend({
  addProseMirrorPlugins() {
    return [...(this.parent?.() ?? []), prismPlugin(this.name)];
  },
});
