# Leanote 前端重写 · Vite + SolidJS + TailwindCSS

重写 [Leanote](https://github.com/leanote/leanote)（蚂蚁笔记）的前端：

- **框架**：SolidJS + TypeScript
- **构建**：Vite 7
- **样式**：TailwindCSS 3（语义色 + CSS 变量，内建明/暗主题）
- **路由**：@solidjs/router
- **富文本编辑器**：TipTap 3（替代原 TinyMCE）
- **Markdown 编辑器**：CodeMirror 6 + marked 实时预览（替代原自写 wmd 编辑器）
- **图标**：lucide-solid

## 已实现

- 落地页、登录、注册、找回密码（接 `/doLogin`、`/doRegister` 等真实端点）
- 三栏笔记工作区：
  - 左：笔记本树（展开/折叠、新建、重命名、删除）+ 标签筛选
  - 中：笔记列表（摘要/列表视图、多种排序、行内移动/删除菜单、搜索）
  - 右：编辑器（富文本 / Markdown 自动切换，只读/编辑切换，自动保存）
- 自动保存（防抖）、⌘/Ctrl+S 保存、⌘/Ctrl+E 切换编辑、明暗主题切换
- 可拖拽调整列宽（持久化到 localStorage）

## 开发

```bash
npm install
npm run dev      # 启动 Vite，默认 http://localhost:5173
```

前端通过 Vite dev proxy 把数据请求转发到运行中的 Go leanote 后端（默认 `http://127.0.0.1:9015`）。可用环境变量覆盖后端地址：

```bash
LEANOTE_BACKEND=http://127.0.0.1:9015 npm run dev
```

代理规则见 `vite.config.ts`：仅转发数据端点（`/note/listNotes`、`/notebook/*`、`/doLogin` 等），页面路由（`/note`、`/note/:id`）由前端 SPA 接管。

## 构建

```bash
npm run build    # tsc -b && vite build → dist/
npm run preview
```

## 鉴权说明

后端使用 cookie 会话（`LEANOTE_SESSION`，`httponly=false`）。前端：
- 通过解析该 cookie 读取当前用户展示信息（`src/lib/session.ts`）；
- 真正的鉴权依据是接口响应——未登录时数据端点 302 跳到 `/login` 或返回 HTML，`src/api/client.ts` 据此抛出 `ApiError{isAuth:true}`。

## 目录结构

```
web-src/
  api/         client.ts（fetch 封装）· types.ts · endpoints.ts
  state/       appStore.ts（全局 store + 动作）· toast.ts
  lib/         session.ts · theme.ts · objectId.ts · format.ts
  components/  layout/ notebook/ notelist/ editor/ ui/
  pages/       HomePage LoginPage RegisterPage FindPasswordPage NotesPage NotFoundPage
```

## 后续阶段

移动端响应式优化。
