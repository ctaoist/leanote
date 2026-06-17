import { Show, For } from "solid-js";
import { A } from "@solidjs/router";
import { BookOpen, Globe, Share2, Users, ArrowRight, Github } from "lucide-solid";
import { BrandLogo } from "../components/Brand";
import { hasSessionCookie } from "../lib/session";

const FEATURES = [
  { icon: BookOpen, title: "知识管理", desc: "笔记本 + 标签双重组织，富文本与 Markdown 自由切换，沉淀你的知识体系。" },
  { icon: Globe, title: "博客发布", desc: "一键将笔记发布为博客，拥有独立主页与主题，把想法分享给世界。" },
  { icon: Share2, title: "随手分享", desc: "笔记、笔记本可按需分享给好友，协作编辑，信息不再孤岛。" },
  { icon: Users, title: "多端协作", desc: "云端同步，桌面、移动、网页多端访问，随时随地继续书写。" },
];

export default function HomePage() {
  const loggedIn = hasSessionCookie();

  return (
    <div class="min-h-dvh bg-bg">
      {/* 顶栏 */}
      <header class="sticky top-0 z-30 border-b border-border/70 bg-bg/80 backdrop-blur">
        <div class="mx-auto flex h-16 max-w-6xl items-center justify-between px-5">
          <BrandLogo size={22} subtitle />
          <nav class="flex items-center gap-2">
            <Show
              when={loggedIn}
              fallback={
                <>
                  <A href="/login" class="btn-ghost">登录</A>
                  <A href="/register" class="btn-primary">免费注册</A>
                </>
              }
            >
              <A href="/note" class="btn-primary gap-1.5">
                进入笔记 <ArrowRight size={16} />
              </A>
            </Show>
          </nav>
        </div>
      </header>

      {/* Hero */}
      <section class="relative overflow-hidden">
        <div class="pointer-events-none absolute inset-0 -z-10">
          <div class="absolute left-1/2 top-0 h-[480px] w-[820px] -translate-x-1/2 rounded-full bg-brand-300/20 blur-3xl" />
        </div>
        <div class="mx-auto max-w-6xl px-5 pb-12 pt-20 text-center">
          <span class="inline-flex items-center rounded-full border border-border bg-surface px-3 py-1 text-xs font-medium text-muted">
            蚂蚁笔记 · 你的私人云端笔记本
          </span>
          <h1 class="mx-auto mt-6 max-w-3xl text-4xl font-bold leading-tight tracking-tight text-fg sm:text-5xl">
            把每一个想法，
            <span class="text-brand-500">妥善安放</span>
          </h1>
          <p class="mx-auto mt-5 max-w-xl text-lg text-muted">
            Leanote 是一款优雅的云笔记应用，支持 Markdown 与富文本、笔记本树、标签、博客发布与分享。
          </p>
          <div class="mt-8 flex items-center justify-center gap-3">
            <A href={loggedIn ? "/note" : "/register"} class="btn-primary h-11 px-6 text-base gap-2">
              {loggedIn ? "进入我的笔记" : "免费开始"} <ArrowRight size={18} />
            </A>
            <a
              href="https://github.com/ctaoist/leanote"
              target="_blank"
              rel="noreferrer"
              class="btn-outline h-11 px-6 text-base gap-2"
            >
              <Github size={18} /> GitHub
            </a>
          </div>

          {/* App 预览 mock */}
          <div class="mx-auto mt-14 max-w-4xl">
            <AppPreview />
          </div>
        </div>
      </section>

      {/* Features */}
      <section class="mx-auto max-w-6xl px-5 py-16">
        <div class="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          <For each={FEATURES}>
            {(f) => (
              <div class="card p-5 transition-shadow hover:shadow-pop">
                <div class="flex h-11 w-11 items-center justify-center rounded-xl bg-brand-500/10 text-brand-600">
                  <f.icon size={22} />
                </div>
                <h3 class="mt-4 text-base font-semibold text-fg">{f.title}</h3>
                <p class="mt-1.5 text-sm leading-relaxed text-muted">{f.desc}</p>
              </div>
            )}
          </For>
        </div>
      </section>

      <footer class="border-t border-border">
        <div class="mx-auto flex max-w-6xl flex-col items-center justify-between gap-2 px-5 py-8 text-sm text-subtle sm:flex-row">
          <BrandLogo size={18} />
          <span>© {new Date().getFullYear()} Leanote · 蚂蚁笔记</span>
        </div>
      </footer>
    </div>
  );
}

/** 纯 CSS 的三栏应用预览 */
function AppPreview() {
  return (
    <div class="overflow-hidden rounded-xl border border-border bg-surface shadow-pop">
      <div class="flex items-center gap-1.5 border-b border-border bg-bg/60 px-4 py-2.5">
        <span class="h-3 w-3 rounded-full bg-red-400" />
        <span class="h-3 w-3 rounded-full bg-amber-400" />
        <span class="h-3 w-3 rounded-full bg-brand-400" />
      </div>
      <div class="grid h-72 grid-cols-[180px_200px_1fr] text-left">
        {/* 笔记本树 */}
        <div class="space-y-2 border-r border-border p-3">
          <div class="h-3 w-16 rounded bg-brand-500/30" />
          <For each={[1, 2, 3, 4]}>
            {(i) => (
              <div class="flex items-center gap-2">
                <div class="h-2.5 w-2.5 rounded-sm bg-muted/40" />
                <div class="h-2.5 rounded bg-muted/25" style={{ width: `${50 + i * 12}px` }} />
              </div>
            )}
          </For>
        </div>
        {/* 笔记列表 */}
        <div class="space-y-2.5 border-r border-border p-3">
          <For each={[0, 1, 2, 3]}>
            {(i) => (
              <div class={`rounded-lg border border-border p-2 ${i === 0 ? "bg-brand-500/5" : ""}`}>
                <div class="h-2.5 w-3/4 rounded bg-fg/15" />
                <div class="mt-1.5 h-2 w-full rounded bg-muted/20" />
              </div>
            )}
          </For>
        </div>
        {/* 编辑器 */}
        <div class="space-y-3 p-5">
          <div class="h-4 w-2/3 rounded bg-fg/20" />
          <div class="space-y-2 pt-2">
            <div class="h-2.5 w-full rounded bg-muted/20" />
            <div class="h-2.5 w-11/12 rounded bg-muted/20" />
            <div class="h-2.5 w-4/5 rounded bg-muted/20" />
            <div class="h-2.5 w-full rounded bg-muted/20" />
            <div class="h-2.5 w-3/4 rounded bg-muted/20" />
          </div>
        </div>
      </div>
    </div>
  );
}
