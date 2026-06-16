import { createSignal, Show } from "solid-js";
import { A } from "@solidjs/router";
import { authApi } from "../api/endpoints";
import { ApiError } from "../api/client";
import { AuthLayout } from "../components/layout/AuthLayout";
import { Button } from "../components/ui/Button";
import { Spinner } from "../components/ui/Spinner";
import { MailCheck } from "lucide-solid";

export default function FindPasswordPage() {
  const [email, setEmail] = createSignal("");
  const [error, setError] = createSignal("");
  const [sent, setSent] = createSignal(false);
  const [loading, setLoading] = createSignal(false);

  const submit = async (e: Event) => {
    e.preventDefault();
    setError("");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email().trim())) return setError("请输入有效的邮箱地址");
    setLoading(true);
    try {
      const re = await authApi.findPassword(email().trim().toLowerCase());
      if (re.Ok) setSent(true);
      else setError(re.Msg || "发送失败");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "网络错误，请重试");
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout
      title="找回密码"
      subtitle="输入注册邮箱，我们会发送重置链接"
      footer={
        <A href="/login" class="font-medium text-brand-600 hover:underline">
          返回登录
        </A>
      }
    >
      <Show
        when={!sent()}
        fallback={
          <div class="flex flex-col items-center gap-3 py-4 text-center">
            <MailCheck size={40} class="text-brand-500" />
            <p class="text-sm text-muted">
              重置链接已发送至 <span class="font-medium text-fg">{email()}</span>，请查收邮件。
            </p>
          </div>
        }
      >
        <form class="space-y-4" onSubmit={submit}>
          <Show when={error()}>
            <div class="rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-600">{error()}</div>
          </Show>
          <div class="space-y-1.5">
            <label class="text-sm font-medium text-fg">邮箱</label>
            <input
              class="input"
              type="email"
              value={email()}
              onInput={(e) => setEmail(e.currentTarget.value)}
              autofocus
            />
          </div>
          <Button type="submit" class="w-full" disabled={loading()}>
            <Show when={loading()} fallback="发送重置链接">
              <Spinner class="h-4 w-4" /> 发送中…
            </Show>
          </Button>
        </form>
      </Show>
    </AuthLayout>
  );
}
