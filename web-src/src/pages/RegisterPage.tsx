import { createSignal, Show } from "solid-js";
import { useNavigate, A } from "@solidjs/router";
import { authApi } from "../api/endpoints";
import { ApiError } from "../api/client";
import { AuthLayout } from "../components/layout/AuthLayout";
import { Button } from "../components/ui/Button";
import { Spinner } from "../components/ui/Spinner";

export default function RegisterPage() {
  const navigate = useNavigate();
  const [email, setEmail] = createSignal("");
  const [pwd, setPwd] = createSignal("");
  const [confirm, setConfirm] = createSignal("");
  const [error, setError] = createSignal("");
  const [loading, setLoading] = createSignal(false);

  const emailValid = (v: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);

  const submit = async (e: Event) => {
    e.preventDefault();
    setError("");
    if (!emailValid(email().trim())) return setError("请输入有效的邮箱地址");
    if (pwd().length < 6) return setError("密码至少 6 位");
    if (pwd() !== confirm()) return setError("两次输入的密码不一致");

    setLoading(true);
    try {
      const re = await authApi.register(email().trim().toLowerCase(), pwd());
      if (re.Ok) {
        // 后端注册成功后会自动登录并种 cookie
        navigate("/note", { replace: true });
      } else {
        setError(re.Msg || "注册失败");
      }
    } catch (err) {
      if (err instanceof ApiError && err.isAuth) {
        setError("当前站点未开放注册");
      } else {
        setError(err instanceof ApiError ? err.message : "网络错误，请重试");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout
      title="注册"
      subtitle="创建账号，开启你的云笔记"
      footer={
        <>
          已有账号？
          <A href="/login" class="ml-1 font-medium text-brand-600 hover:underline">
            去登录
          </A>
        </>
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
            autocomplete="email"
            value={email()}
            onInput={(e) => setEmail(e.currentTarget.value)}
            autofocus
          />
        </div>

        <div class="space-y-1.5">
          <label class="text-sm font-medium text-fg">密码</label>
          <input
            class="input"
            type="password"
            autocomplete="new-password"
            value={pwd()}
            onInput={(e) => setPwd(e.currentTarget.value)}
          />
        </div>

        <div class="space-y-1.5">
          <label class="text-sm font-medium text-fg">确认密码</label>
          <input
            class="input"
            type="password"
            autocomplete="new-password"
            value={confirm()}
            onInput={(e) => setConfirm(e.currentTarget.value)}
          />
        </div>

        <Button type="submit" class="w-full" disabled={loading()}>
          <Show when={loading()} fallback="注册">
            <Spinner class="h-4 w-4" /> 注册中…
          </Show>
        </Button>
      </form>
    </AuthLayout>
  );
}
