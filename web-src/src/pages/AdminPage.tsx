import { createSignal, onMount, Show, Switch, Match, type JSX } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { ArrowLeft, LayoutDashboard, Users, Settings, Image, Newspaper, Loader2 } from "lucide-solid";
import { bootstrapApi } from "../api/endpoints";
import { BrandLogo } from "../components/Brand";
import { Dashboard } from "../components/admin/Dashboard";
import { UsersPanel } from "../components/admin/UsersPanel";
import { SettingsPanel } from "../components/admin/SettingsPanel";
import { ImageBedPanel } from "../components/admin/ImageBedPanel";
import { BlogPanel } from "../components/admin/BlogPanel";

type Tab = "dashboard" | "users" | "settings" | "imagebed" | "blog";

export default function AdminPage() {
  const navigate = useNavigate();
  const [ready, setReady] = createSignal(false);
  const [isAdmin, setIsAdmin] = createSignal(false);
  // 普通用户默认进图床；管理员默认进仪表盘。
  const [tab, setTab] = createSignal<Tab>("imagebed");

  // 守卫：未登录→登录页。登录用户都可进（普通用户只看图床；管理员多出管理类 Tab）。
  onMount(async () => {
    const user = await bootstrapApi.fetchUserInfo();
    if (!user) {
      navigate("/login?from=/admin", { replace: true });
      return;
    }
    const admin = !!user.IsAdmin;
    setIsAdmin(admin);
    setTab(admin ? "dashboard" : "imagebed");
    setReady(true);
  });

  return (
    <Show
      when={ready()}
      fallback={
        <div class="flex h-dvh items-center justify-center text-muted">
          <Loader2 size={26} class="animate-spin" />
        </div>
      }
    >
      <div class="flex h-dvh flex-col bg-bg text-fg">
        <header class="flex h-14 shrink-0 items-center gap-3 border-b border-border px-4">
          <button
            type="button"
            class="btn-ghost inline-flex h-9 items-center gap-1.5 px-2.5 text-sm"
            onClick={() => navigate("/note")}
          >
            <ArrowLeft size={16} /> 返回笔记
          </button>
          <div class="mx-1 h-6 w-px bg-border" />
          <BrandLogo size={18} />
          <span class="ml-1 rounded-md bg-brand-500/10 px-2 py-0.5 text-xs font-medium text-brand-600">
            设置
          </span>
        </header>

        <div class="flex min-h-0 flex-1 flex-col lg:flex-row">
          <nav class="flex shrink-0 gap-1 overflow-x-auto no-scrollbar border-b border-border p-2 lg:w-52 lg:flex-col lg:space-y-1 lg:overflow-visible lg:border-b-0 lg:border-r lg:p-3">
            <Show when={isAdmin()}>
              <NavItem active={tab() === "dashboard"} icon={<LayoutDashboard size={17} />} onClick={() => setTab("dashboard")}>
                仪表盘
              </NavItem>
              <NavItem active={tab() === "users"} icon={<Users size={17} />} onClick={() => setTab("users")}>
                用户管理
              </NavItem>
              <NavItem active={tab() === "settings"} icon={<Settings size={17} />} onClick={() => setTab("settings")}>
                全局设置
              </NavItem>
            </Show>
            <NavItem active={tab() === "imagebed"} icon={<Image size={17} />} onClick={() => setTab("imagebed")}>
              图床设置
            </NavItem>
            <NavItem active={tab() === "blog"} icon={<Newspaper size={17} />} onClick={() => setTab("blog")}>
              博客设置
            </NavItem>
          </nav>

          <main class="min-w-0 flex-1 overflow-y-auto p-6">
            <Switch>
              <Match when={tab() === "dashboard" && isAdmin()}>
                <Dashboard />
              </Match>
              <Match when={tab() === "users" && isAdmin()}>
                <UsersPanel />
              </Match>
              <Match when={tab() === "settings" && isAdmin()}>
                <SettingsPanel />
              </Match>
              <Match when={tab() === "imagebed"}>
                <ImageBedPanel />
              </Match>
              <Match when={tab() === "blog"}>
                <BlogPanel />
              </Match>
            </Switch>
          </main>
        </div>
      </div>
    </Show>
  );
}

function NavItem(props: { active: boolean; icon: JSX.Element; onClick: () => void; children: JSX.Element }) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      class={`flex w-auto shrink-0 items-center gap-2.5 whitespace-nowrap rounded-lg px-3 py-2 text-sm font-medium transition-colors lg:w-full
        ${props.active ? "bg-brand-500/10 text-brand-600" : "text-muted hover:bg-black/5 hover:text-fg dark:hover:bg-white/5"}`}
    >
      {props.icon}
      {props.children}
    </button>
  );
}
