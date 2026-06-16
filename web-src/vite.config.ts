import { defineConfig, type ProxyOptions } from "vite";
import solid from "vite-plugin-solid";

// 新 Go/Fiber 后端默认监听 :9016（旧 Revel 仍可在 :9015 对照）。
const BACKEND = process.env.LEANOTE_BACKEND || "http://127.0.0.1:9016";

// 仅把「数据端点」转发到后端；页面路由（/note、/note/:id）由 SPA 接管。
// 这些 key 既可以是前缀，也可以是正则（以 ^ 开头）。
const proxyTargets: Record<string, true> = {
  // 笔记数据端点（用方法名白名单，避免与页面路由 /note/:id 冲突）
  "^/note/(listNotes|listTrashNotes|getNoteAndContent|getNoteContent|updateNoteOrContent|deleteNote|deleteTrash|moveNote|copyNote|copySharedNote|searchNote|searchNoteByTags|setNote2Blog|exportPdf|toPdf|getNoteAndContentBySrc)": true,
  "^/noteContentHistory/": true,
  "^/notebook/": true,
  "^/tag/": true,
  "^/attach/": true,
  "^/file/": true,
  "^/user/": true,
  "^/blog/": true,
  "^/album/": true,
  // 管理后台数据端点。只匹配带斜杠的 /admin/xxx；裸 /admin（页面路由）不匹配，
  // 仍由 SPA fallback 接管 —— 与 /note vs /note/listNotes 同一套机制。
  "^/admin/": true,
  // 认证
  "^/doLogin": true,
  "^/logout": true,
  "^/doRegister": true,
  "^/doFindPassword": true,
  "^/findPasswordUpdate": true,
  // 杂项 / 静态资源（验证码、头像图片等仍走后端）
  "^/api/": true,
  "^/captcha/": true,
  "^/upload/": true,
  "^/images/": true,
  "^/public/": true,
};

const proxy: Record<string, ProxyOptions> = Object.fromEntries(
  Object.keys(proxyTargets).map((key) => [
    key,
    { target: BACKEND, changeOrigin: true, secure: false },
  ])
);

export default defineConfig({
  plugins: [solid()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    proxy,
  },
  preview: {
    host: "0.0.0.0",
    port: 4173,
    proxy,
  },
  build: {
    target: "es2020",
    // 输出落到 web-src/dist，根目录的 go:embed 直接打进二进制（`go build` 前先构建前端）。
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: {
      output: {
        // 把重型供应商库拆成各自命名 chunk。配合 NoteEditor 的懒加载，
        // tiptap / markdown-it+prism 只在打开对应类型笔记/历史时才加载，不再压进
        // 初始 NotesPage chunk。codemirror 不在此强拆 —— 它的 @codemirror/language-data
        // 靠动态 import 按需加载各语言语法，强并一个 chunk 反而会把这些懒加载语言
        // 全部塞进一个 1.5MB 巨包。katex/mermaid/cytoscape 已由动态 import 自动拆分。
        manualChunks(id) {
          // prismjs core+components AND our wrapper (lib/prism, lib/prismCore)
          // must live in ONE chunk so the global-Prism pin (prismCore) evaluates
          // before the language components that reference a global `Prism` —
          // otherwise the prod build throws "Prism is not defined". Checked
          // before the node_modules early-return so the app-side wrapper is
          // pulled in too.
          if (id.includes("prismjs") || id.includes("/lib/prism")) return "vendor-prism";
          if (!id.includes("node_modules")) return;
          if (id.includes("@tiptap") || id.includes("prosemirror")) return "vendor-tiptap";
          if (
            id.includes("markdown-it") ||
            id.includes("uc.micro") ||
            id.includes("linkify-it") ||
            id.includes("mdurl") ||
            id.includes("punycode") ||
            id.includes("entities")
          ) {
            return "vendor-markdownit";
          }
        },
      },
    },
  },
});
