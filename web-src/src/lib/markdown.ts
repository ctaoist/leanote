// 共享 Markdown 渲染管线：markdown-it + Prism 代码高亮 + KaTeX 公式 +
// 块级 data-line 锚点（供分栏编辑器同步滚动）。mermaid 因渲染异步，单独走
// renderMermaid() 的渲染后 DOM pass。编辑器预览与历史弹窗共用这一份配置。
import MarkdownIt from "markdown-it";
import markdownItKatexRaw from "@vscode/markdown-it-katex";
import "katex/dist/katex.min.css";

// Prism 实例与语言归一从共享模块取（与富文本代码块高亮共用同一份配置）。
import { Prism, normalizeLang } from "./prism";

// @vscode/markdown-it-katex 是 CommonJS 包（exports.default = 函数）。不同打包/
// 依赖优化（vite optimizeDeps 的 interop）下，默认导出可能是函数本身，也可能被
// 包成 { default: fn }（甚至再嵌一层）。逐层解到函数为止，否则 markdown-it 的
// .use() 会对一个对象调 .apply → "plugin.apply is not a function"。
function unwrapPlugin(m: unknown): any {
  let p: any = m;
  while (p && typeof p !== "function" && p.default) p = p.default;
  return p;
}
const markdownItKatex: any = unwrapPlugin(markdownItKatexRaw);

export const md: MarkdownIt = new MarkdownIt({
  html: true,
  linkify: true,
  breaks: true,
  // 返回「内层 HTML」而非完整 <pre>，markdown-it 仍会用 <pre><code class="language-x"
  // data-line=".."> 包裹 —— 既得到 Prism 高亮，又保住 data-line 锚点。
  // mermaid 不在此高亮：返回空串让其原样转义，靠 code.language-mermaid 类供后处理识别。
  highlight(code, lang) {
    const name = normalizeLang(lang);
    if (name && name !== "mermaid" && Prism.languages[name]) {
      try {
        return Prism.highlight(code, Prism.languages[name], name);
      } catch {
        /* 落到默认转义 */
      }
    }
    return "";
  },
});

md.use(markdownItKatex, { throwOnError: false });

// ----- 块级 data-line 注入（源行，0 基，来自 token.map）-----
type MdToken = Parameters<typeof md.renderer.renderToken>[0][number];
function tagLine(token: MdToken) {
  if (token.map) token.attrSet("data-line", String(token.map[0]));
}
const defaultRenderToken = md.renderer.renderToken.bind(md.renderer);
md.renderer.renderToken = (tokens, idx, options) => {
  const token = tokens[idx];
  if (token.level === 0 && token.nesting === 1 && token.map) tagLine(token);
  return defaultRenderToken(tokens, idx, options);
};
(["fence", "code_block"] as const).forEach((name) => {
  const orig = md.renderer.rules[name];
  md.renderer.rules[name] = (tokens, idx, options, env, slf) => {
    const token = tokens[idx];
    if (token.level === 0 && token.map) tagLine(token);
    return orig
      ? orig(tokens, idx, options, env, slf)
      : slf.renderToken(tokens, idx, options);
  };
});

export function renderMarkdown(src: string): string {
  return md.render(src || "");
}

// ----- 预览代码块：悬浮「复制」按钮 -----
// 预览区是 innerHTML，每次重渲会清掉旧按钮，故每次渲染后重新注入（幂等、廉价）。
const COPY_ICON =
  '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>';
const CHECK_ICON =
  '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>';

function copyText(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) return navigator.clipboard.writeText(text);
  // 非安全上下文回退
  return new Promise((resolve, reject) => {
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
      resolve();
    } catch (e) {
      reject(e);
    }
  });
}

/** 给容器内每个代码块 <pre> 注入右上角悬浮复制按钮（跳过 mermaid，幂等）。 */
export function decorateCodeBlocks(container: HTMLElement): void {
  container.querySelectorAll<HTMLPreElement>("pre").forEach((pre) => {
    const code = pre.querySelector("code");
    if (!code || code.classList.contains("language-mermaid")) return;
    if (pre.querySelector(":scope > .code-copy-btn")) return; // 已注入

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "code-copy-btn";
    btn.setAttribute("aria-label", "复制代码");
    btn.title = "复制";
    btn.innerHTML = COPY_ICON;
    let timer: ReturnType<typeof setTimeout> | undefined;
    btn.addEventListener("click", () => {
      void copyText(code.textContent ?? "").then(() => {
        btn.classList.add("copied");
        btn.innerHTML = CHECK_ICON;
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => {
          btn.classList.remove("copied");
          btn.innerHTML = COPY_ICON;
        }, 1400);
      });
    });
    pre.appendChild(btn);
  });
}

// ----- mermaid：懒加载 + 渲染后 DOM pass -----
type MermaidApi = {
  initialize: (cfg: Record<string, unknown>) => void;
  // 校验语法；suppressErrors 时非法返回 false 而不抛错、也不往 DOM 注入错误图
  parse: (src: string, opts?: { suppressErrors?: boolean }) => Promise<unknown>;
  render: (id: string, src: string) => Promise<{ svg: string }>;
};
let mermaidApi: MermaidApi | null = null;
let mermaidDark: boolean | null = null;
let renderSeq = 0;
// 按源码字符串缓存渲染好的 SVG，避免每次按键重渲（仅主题切换时清空）。
const svgCache = new Map<string, string>();

/**
 * 把容器内的 ```mermaid 代码块替换为渲染好的 SVG。
 * 首次调用时动态 import mermaid（约 500KB，不入初始包）。
 */
export async function renderMermaid(container: HTMLElement, dark: boolean): Promise<void> {
  const blocks = Array.from(
    container.querySelectorAll<HTMLElement>("code.language-mermaid")
  );
  if (!blocks.length) return;

  if (!mermaidApi) {
    mermaidApi = (await import("mermaid")).default as unknown as MermaidApi;
  }
  if (mermaidDark !== dark) {
    mermaidApi.initialize({
      startOnLoad: false,
      theme: dark ? "dark" : "default",
      securityLevel: "loose",
      fontFamily: "inherit",
      // 编辑过程中正文常是「半成品」的非法 mermaid，禁止 mermaid 把
      // 「Syntax error in text」错误图自行塞进 document.body（否则会悬在页面底部）。
      suppressErrorRendering: true,
    });
    mermaidDark = dark;
    svgCache.clear();
  }

  for (const code of blocks) {
    const pre = code.closest("pre") ?? code;
    const src = (code.textContent ?? "").trim();
    if (!src) continue;

    const cached = svgCache.get(src);
    if (cached) {
      const wrap = document.createElement("div");
      wrap.className = "mermaid";
      wrap.innerHTML = cached;
      pre.replaceWith(wrap);
      continue;
    }

    // 先校验：编辑中途语法不合法时保留原代码块、不渲染（也不弹错误图）。
    let valid = false;
    try {
      valid = (await mermaidApi.parse(src, { suppressErrors: true })) !== false;
    } catch {
      valid = false;
    }
    if (!valid) {
      pre.setAttribute("data-mermaid-error", "1");
      continue;
    }

    try {
      const { svg } = await mermaidApi.render(`mmd-${++renderSeq}`, src);
      svgCache.set(src, svg);
      const wrap = document.createElement("div");
      wrap.className = "mermaid";
      wrap.innerHTML = svg;
      pre.replaceWith(wrap);
    } catch {
      pre.setAttribute("data-mermaid-error", "1");
    }
  }

  // 防御：清掉 mermaid 渲染/测量时可能遗留在 <body> 末尾的临时节点（含错误图）。
  document
    .querySelectorAll('body > [id^="dmmd-"], body > [id^="mmd-"]')
    .forEach((el) => el.remove());
}
