import { createSignal, Show } from "solid-js";
import { useNavigate, useSearchParams, A } from "@solidjs/router";
import { authApi } from "../api/endpoints";
import { ApiError } from "../api/client";
import { AuthLayout } from "../components/layout/AuthLayout";
import { Button } from "../components/ui/Button";
import { Spinner } from "../components/ui/Spinner";
import { RefreshCw } from "lucide-solid";

export default function LoginPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();

  const [email, setEmail] = createSignal("");
  const [pwd, setPwd] = createSignal("");
  const [captcha, setCaptcha] = createSignal("");
  const [needCaptcha, setNeedCaptcha] = createSignal(false);
  const [captchaSrc, setCaptchaSrc] = createSignal(authApi.captchaUrl());
  const [error, setError] = createSignal("");
  const [loading, setLoading] = createSignal(false);

  const reloadCaptcha = () => setCaptchaSrc(authApi.captchaUrl());

  const submit = async (e: Event) => {
    e.preventDefault();
    setError("");
    if (!email().trim()) return setError("请输入用户名或邮箱");
    if (!pwd()) return setError("请输入密码");
    if (pwd().length < 6) return setError("密码至少 6 位");
    if (needCaptcha() && !captcha()) return setError("请输入验证码");

    setLoading(true);
    try {
      const re = await authApi.login(email().trim(), pwd(), captcha());
      if (re.Ok) {
        const from = (params.from as string) || "/note";
        navigate(from, { replace: true });
      } else {
        if (re.Item) {
          setNeedCaptcha(true);
          reloadCaptcha();
        }
        setError(re.Msg || "登录失败");
      }
    } catch (err) {
      const re = err instanceof ApiError ? (err.payload as { Item?: boolean }) : null;
      if (re?.Item) {
        setNeedCaptcha(true);
        reloadCaptcha();
      }
      setError(err instanceof ApiError ? err.message : "网络错误，请重试");
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout
      title="登录"
      subtitle="欢迎回来，继续记录你的想法"
      footer={
        <>
          还没有账号？
          <A href="/register" class="ml-1 font-medium text-brand-600 hover:underline">
            立即注册
          </A>
        </>
      }
    >
      <form class="space-y-4" onSubmit={submit}>
        <Show when={error()}>
          <div class="rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-600">{error()}</div>
        </Show>

        <div class="space-y-1.5">
          <label class="text-sm font-medium text-fg">用户名或邮箱</label>
          <input
            class="input"
            type="text"
            autocomplete="username"
            value={email()}
            onInput={(e) => setEmail(e.currentTarget.value)}
            autofocus
          />
        </div>

        <div class="space-y-1.5">
          <div class="flex items-center justify-between">
            <label class="text-sm font-medium text-fg">密码</label>
            <A href="/findPassword" class="text-xs text-muted hover:text-brand-600">
              忘记密码？
            </A>
          </div>
          <input
            class="input"
            type="password"
            autocomplete="current-password"
            value={pwd()}
            onInput={(e) => setPwd(e.currentTarget.value)}
          />
        </div>

        <Show when={needCaptcha()}>
          <div class="space-y-1.5">
            <label class="text-sm font-medium text-fg">验证码</label>
            <div class="flex items-center gap-2">
              <input
                class="input flex-1"
                type="text"
                value={captcha()}
                onInput={(e) => setCaptcha(e.currentTarget.value)}
              />
              <button
                type="button"
                class="flex h-10 items-center gap-1.5 rounded-lg border border-border px-2"
                onClick={reloadCaptcha}
                title="换一张"
              >
                <img src={captchaSrc()} alt="captcha" class="h-7" />
                <RefreshCw size={14} class="text-muted" />
              </button>
            </div>
          </div>
        </Show>

        <Button type="submit" class="w-full" disabled={loading()}>
          <Show when={loading()} fallback="登录">
            <Spinner class="h-4 w-4" /> 登录中…
          </Show>
        </Button>
      </form>
    </AuthLayout>
  );
}
