import { createResource, Show, type JSX } from "solid-js";
import { Users, FileText, Globe, Loader2 } from "lucide-solid";
import { adminApi } from "../../api/endpoints";

export function Dashboard() {
  const [stats] = createResource(() => adminApi.stats());

  return (
    <div>
      <h1 class="mb-1 text-xl font-semibold text-fg">仪表盘</h1>
      <p class="mb-6 text-sm text-subtle">站点总览</p>

      <Show
        when={!stats.loading}
        fallback={
          <div class="flex h-32 items-center justify-center text-muted">
            <Loader2 size={22} class="animate-spin" />
          </div>
        }
      >
        <Show when={stats()} fallback={<p class="text-sm text-rose-500">加载统计失败</p>}>
          {(s) => (
            <div class="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <StatCard icon={<Users size={20} />} label="用户总数" value={s().UserCount} />
              <StatCard icon={<FileText size={20} />} label="笔记总数" value={s().NoteCount} />
              <StatCard icon={<Globe size={20} />} label="博客笔记" value={s().BlogCount} />
            </div>
          )}
        </Show>
      </Show>
    </div>
  );
}

function StatCard(props: { icon: JSX.Element; label: string; value: number }) {
  return (
    <div class="card flex items-center gap-4 p-5">
      <span class="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-brand-500/10 text-brand-600">
        {props.icon}
      </span>
      <div class="min-w-0">
        <div class="text-2xl font-bold text-fg">{props.value.toLocaleString()}</div>
        <div class="text-sm text-muted">{props.label}</div>
      </div>
    </div>
  );
}
