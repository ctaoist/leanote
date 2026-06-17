import { A } from "@solidjs/router";
import type { JSX } from "solid-js";
import { BrandLogo } from "../Brand";

interface AuthLayoutProps {
  title: string;
  subtitle?: string;
  children: JSX.Element;
  footer?: JSX.Element;
}

export function AuthLayout(props: AuthLayoutProps) {
  return (
    <div class="relative flex min-h-dvh flex-col items-center justify-center overflow-hidden bg-bg px-4 py-10">
      {/* 背景装饰：品牌绿光晕 */}
      <div class="pointer-events-none absolute inset-0 -z-10">
        <div class="absolute -left-32 -top-32 h-96 w-96 rounded-full bg-brand-300/30 blur-3xl" />
        <div class="absolute -bottom-40 -right-24 h-96 w-96 rounded-full bg-brand-500/20 blur-3xl" />
      </div>

      <A href="/" class="mb-7">
        <BrandLogo size={26} subtitle />
      </A>

      <div class="w-full max-w-[400px] card p-7">
        <div class="mb-6 text-center">
          <h1 class="text-xl font-semibold text-fg">{props.title}</h1>
          {props.subtitle && <p class="mt-1 text-sm text-muted">{props.subtitle}</p>}
        </div>
        {props.children}
      </div>

      <div class="mt-6 text-center text-sm text-subtle">{props.footer}</div>

      <footer class="mt-10 text-xs text-subtle">
        © {new Date().getFullYear()} Leanote · 蚂蚁笔记
      </footer>
    </div>
  );
}
