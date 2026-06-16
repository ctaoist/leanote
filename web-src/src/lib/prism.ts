// 共享 Prism 实例与语言配置。Markdown 预览管线（lib/markdown.ts）与富文本
// 代码块高亮插件（editor/codeBlockPrism.ts）共用同一份 Prism，避免重复打包，
// 并保证两处高亮配色一致（都命中 app.css 里 `.prose .token.*` 主题）。
//
// ./prismCore 必须最先 import —— 它把 Prism 钉到 globalThis 上，供下面那些
// 引用「全局 Prism」的语言组件在 production 构建里也能找到（否则报
// "Prism is not defined"）。
import Prism from "./prismCore";

// 核心已含 markup/css/clike/javascript，其余按依赖顺序补充。
import "prismjs/components/prism-typescript";
import "prismjs/components/prism-jsx";
import "prismjs/components/prism-tsx";
import "prismjs/components/prism-json";
import "prismjs/components/prism-bash";
import "prismjs/components/prism-python";
import "prismjs/components/prism-go";
import "prismjs/components/prism-rust";
import "prismjs/components/prism-java";
import "prismjs/components/prism-c";
import "prismjs/components/prism-cpp";
import "prismjs/components/prism-sql";
import "prismjs/components/prism-yaml";
import "prismjs/components/prism-markdown";
import "prismjs/components/prism-diff";

// 不让 Prism 在页面加载时自动扫描 DOM —— 我们只手动调用 Prism.highlight/tokenize。
Prism.manual = true;

// 语言别名归一
const langAlias: Record<string, string> = {
  js: "javascript",
  ts: "typescript",
  sh: "bash",
  shell: "bash",
  yml: "yaml",
  html: "markup",
  xml: "markup",
  svg: "markup",
  "c++": "cpp",
};

/** 归一语言名（小写 + 别名映射）；空串表示无语言。 */
export function normalizeLang(lang: string | null | undefined): string {
  if (!lang) return "";
  const l = lang.toLowerCase();
  return langAlias[l] || l;
}

/** 归一后该语言是否有可用 Prism 语法。 */
export function hasGrammar(lang: string | null | undefined): boolean {
  const name = normalizeLang(lang);
  return !!name && !!Prism.languages[name];
}

/** 富文本工具栏代码块语言下拉的候选项（与上面 import 的语言对应）。 */
export const PRISM_LANGUAGES: { value: string; label: string }[] = [
  { value: "", label: "纯文本" },
  { value: "javascript", label: "JavaScript" },
  { value: "typescript", label: "TypeScript" },
  { value: "jsx", label: "JSX" },
  { value: "tsx", label: "TSX" },
  { value: "json", label: "JSON" },
  { value: "bash", label: "Bash" },
  { value: "python", label: "Python" },
  { value: "go", label: "Go" },
  { value: "rust", label: "Rust" },
  { value: "java", label: "Java" },
  { value: "c", label: "C" },
  { value: "cpp", label: "C++" },
  { value: "sql", label: "SQL" },
  { value: "yaml", label: "YAML" },
  { value: "markup", label: "HTML/XML" },
  { value: "css", label: "CSS" },
  { value: "markdown", label: "Markdown" },
  { value: "diff", label: "Diff" },
];

export { Prism };
