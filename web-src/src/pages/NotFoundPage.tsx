import { A } from "@solidjs/router";

export default function NotFoundPage() {
  return (
    <div class="flex min-h-screen flex-col items-center justify-center gap-4">
      <h1 class="text-6xl font-bold text-brand-500">404</h1>
      <p class="text-muted">页面走丢了</p>
      <A href="/" class="btn-primary">
        返回首页
      </A>
    </div>
  );
}
