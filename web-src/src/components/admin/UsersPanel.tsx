import { createResource, createSignal, For, Show } from "solid-js";
import { Search, UserPlus, KeyRound, ChevronLeft, ChevronRight, ArrowUp, ArrowDown, BadgeCheck, Loader2 } from "lucide-solid";
import { Modal } from "../ui/Modal";
import { Button } from "../ui/Button";
import { adminApi } from "../../api/endpoints";
import type { AdminUserRow } from "../../api/types";
import { pushToast } from "../../state/toast";

const PAGE_SIZE = 10;
type SortField = "email" | "username" | "verified" | "createdTime";

export function UsersPanel() {
  const [keywords, setKeywords] = createSignal("");
  const [applied, setApplied] = createSignal("");
  const [page, setPage] = createSignal(1);
  const [sortField, setSortField] = createSignal<SortField>("createdTime");
  const [asc, setAsc] = createSignal(false);
  const [showAdd, setShowAdd] = createSignal(false);
  const [resetUser, setResetUser] = createSignal<AdminUserRow | null>(null);

  const sorter = () => `${sortField()}-${asc() ? "up" : "down"}`;
  const [data, { refetch }] = createResource(
    () => ({ page: page(), sorter: sorter(), keywords: applied() }),
    (p) => adminApi.listUsers({ page: p.page, pageSize: PAGE_SIZE, sorter: p.sorter, keywords: p.keywords })
  );

  const totalPages = () => Math.max(1, Math.ceil((data()?.Count ?? 0) / PAGE_SIZE));

  const applySearch = () => {
    setPage(1);
    setApplied(keywords().trim());
  };

  const toggleSort = (field: SortField) => {
    if (sortField() === field) setAsc((v) => !v);
    else {
      setSortField(field);
      setAsc(false);
    }
    setPage(1);
  };

  return (
    <div>
      <div class="mb-5 flex items-center justify-between gap-3">
        <div>
          <h1 class="text-xl font-semibold text-fg">用户管理</h1>
          <p class="text-sm text-subtle">共 {data()?.Count ?? 0} 个用户</p>
        </div>
        <Button variant="primary" onClick={() => setShowAdd(true)}>
          <UserPlus size={15} /> 新增用户
        </Button>
      </div>

      {/* 搜索 */}
      <div class="mb-3 flex gap-2">
        <div class="relative flex-1 max-w-xs">
          <Search size={15} class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-subtle" />
          <input
            class="input pl-9"
            placeholder="搜索邮箱 / 用户名"
            value={keywords()}
            onInput={(e) => setKeywords(e.currentTarget.value)}
            onKeyDown={(e) => e.key === "Enter" && applySearch()}
          />
        </div>
        <Button variant="outline" onClick={applySearch}>
          搜索
        </Button>
      </div>

      {/* 表格 */}
      <div class="card overflow-hidden">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-border bg-black/[0.02] text-left text-xs text-muted dark:bg-white/[0.02]">
              <Th label="邮箱" field="email" sortField={sortField()} asc={asc()} onSort={toggleSort} />
              <Th label="用户名" field="username" sortField={sortField()} asc={asc()} onSort={toggleSort} />
              <Th label="已验证" field="verified" sortField={sortField()} asc={asc()} onSort={toggleSort} />
              <Th label="注册时间" field="createdTime" sortField={sortField()} asc={asc()} onSort={toggleSort} />
              <th class="px-4 py-2.5 text-right font-medium">操作</th>
            </tr>
          </thead>
          <tbody>
            <Show
              when={!data.loading}
              fallback={
                <tr>
                  <td colspan={5} class="px-4 py-10 text-center text-muted">
                    <Loader2 size={20} class="mx-auto animate-spin" />
                  </td>
                </tr>
              }
            >
              <Show
                when={(data()?.List?.length ?? 0) > 0}
                fallback={
                  <tr>
                    <td colspan={5} class="px-4 py-10 text-center text-subtle">没有用户</td>
                  </tr>
                }
              >
                <For each={data()?.List}>
                  {(u) => (
                    <tr class="border-b border-border last:border-0 hover:bg-black/[0.015] dark:hover:bg-white/[0.02]">
                      <td class="px-4 py-2.5 text-fg">{u.Email}</td>
                      <td class="px-4 py-2.5 text-fg">{u.Username}</td>
                      <td class="px-4 py-2.5">
                        <Show when={u.Verified} fallback={<span class="text-subtle">未验证</span>}>
                          <span class="inline-flex items-center gap-1 text-brand-600">
                            <BadgeCheck size={15} /> 已验证
                          </span>
                        </Show>
                      </td>
                      <td class="px-4 py-2.5 text-muted">{formatDate(u.CreatedTime)}</td>
                      <td class="px-4 py-2.5 text-right">
                        <button
                          type="button"
                          class="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs text-muted hover:bg-black/5 hover:text-fg dark:hover:bg-white/5"
                          onClick={() => setResetUser(u)}
                        >
                          <KeyRound size={13} /> 重置密码
                        </button>
                      </td>
                    </tr>
                  )}
                </For>
              </Show>
            </Show>
          </tbody>
        </table>
      </div>

      {/* 分页 */}
      <div class="mt-4 flex items-center justify-end gap-2 text-sm text-muted">
        <span>
          第 {page()} / {totalPages()} 页
        </span>
        <button
          type="button"
          class="btn-ghost h-8 w-8 disabled:opacity-40"
          disabled={page() <= 1}
          onClick={() => setPage((p) => Math.max(1, p - 1))}
        >
          <ChevronLeft size={16} />
        </button>
        <button
          type="button"
          class="btn-ghost h-8 w-8 disabled:opacity-40"
          disabled={page() >= totalPages()}
          onClick={() => setPage((p) => Math.min(totalPages(), p + 1))}
        >
          <ChevronRight size={16} />
        </button>
      </div>

      <AddUserModal
        open={showAdd()}
        onClose={() => setShowAdd(false)}
        onAdded={() => {
          setShowAdd(false);
          setPage(1);
          void refetch();
        }}
      />
      <ResetPwdModal user={resetUser()} onClose={() => setResetUser(null)} />
    </div>
  );
}

function Th(props: {
  label: string;
  field: SortField;
  sortField: SortField;
  asc: boolean;
  onSort: (f: SortField) => void;
}) {
  const active = () => props.sortField === props.field;
  return (
    <th class="px-4 py-2.5 font-medium">
      <button type="button" class="inline-flex items-center gap-1 hover:text-fg" onClick={() => props.onSort(props.field)}>
        {props.label}
        <Show when={active()} fallback={<span class="w-3" />}>
          <Show when={props.asc} fallback={<ArrowDown size={12} />}>
            <ArrowUp size={12} />
          </Show>
        </Show>
      </button>
    </th>
  );
}

function AddUserModal(props: { open: boolean; onClose: () => void; onAdded: () => void }) {
  const [email, setEmail] = createSignal("");
  const [pwd, setPwd] = createSignal("");
  const [saving, setSaving] = createSignal(false);

  const submit = async () => {
    if (!email().trim() || !pwd()) return pushToast("请填写邮箱和密码", "error");
    if (pwd().length < 6) return pushToast("密码至少 6 位", "error");
    setSaving(true);
    try {
      await adminApi.addUser(email().trim(), pwd());
      pushToast("用户已创建", "success");
      setEmail("");
      setPwd("");
      props.onAdded();
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "创建失败", "error");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={props.open}
      onClose={props.onClose}
      title="新增用户"
      footer={
        <>
          <Button variant="outline" onClick={props.onClose}>
            取消
          </Button>
          <Button variant="primary" disabled={saving()} onClick={() => void submit()}>
            <Show when={saving()}>
              <Loader2 size={14} class="animate-spin" />
            </Show>
            创建
          </Button>
        </>
      }
    >
      <div class="space-y-4">
        <div>
          <label class="mb-1.5 block text-sm font-medium text-fg">邮箱</label>
          <input class="input" value={email()} onInput={(e) => setEmail(e.currentTarget.value)} placeholder="user@example.com" />
        </div>
        <div>
          <label class="mb-1.5 block text-sm font-medium text-fg">初始密码</label>
          <input class="input" type="password" value={pwd()} onInput={(e) => setPwd(e.currentTarget.value)} placeholder="至少 6 位" />
        </div>
      </div>
    </Modal>
  );
}

function ResetPwdModal(props: { user: AdminUserRow | null; onClose: () => void }) {
  const [pwd, setPwd] = createSignal("");
  const [saving, setSaving] = createSignal(false);

  const submit = async () => {
    const u = props.user;
    if (!u) return;
    if (pwd().length < 6) return pushToast("密码至少 6 位", "error");
    setSaving(true);
    try {
      await adminApi.resetPwd(u.UserId, pwd());
      pushToast("密码已重置", "success");
      setPwd("");
      props.onClose();
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "重置失败", "error");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={!!props.user}
      onClose={props.onClose}
      title="重置密码"
      footer={
        <>
          <Button variant="outline" onClick={props.onClose}>
            取消
          </Button>
          <Button variant="primary" disabled={saving()} onClick={() => void submit()}>
            <Show when={saving()}>
              <Loader2 size={14} class="animate-spin" />
            </Show>
            确认重置
          </Button>
        </>
      }
    >
      <p class="mb-3 text-sm text-muted">
        为 <span class="font-medium text-fg">{props.user?.Email}</span> 设置新密码
      </p>
      <input class="input" type="password" value={pwd()} onInput={(e) => setPwd(e.currentTarget.value)} placeholder="新密码（至少 6 位）" />
    </Modal>
  );
}

function formatDate(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleDateString("zh-CN", { year: "numeric", month: "2-digit", day: "2-digit" });
}
