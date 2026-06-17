import { createSignal, Show, Switch, Match } from "solid-js";
import { Upload, BadgeCheck, AlertCircle, Loader2 } from "lucide-solid";
import { Modal } from "../ui/Modal";
import { Button } from "../ui/Button";
import { Avatar } from "../ui/Avatar";
import { appState, actions } from "../../state/appStore";
import { userApi, fileApi } from "../../api/endpoints";
import { pushToast } from "../../state/toast";
import { avatarUrl } from "../../lib/url";
import {
  autoSaveMs,
  setAutoSaveMs,
  AUTOSAVE_DEFAULT_MS,
  AUTOSAVE_MIN_MS,
  AUTOSAVE_MAX_MS,
} from "../../lib/prefs";

interface AccountModalProps {
  open: boolean;
  onClose: () => void;
}

type Tab = "profile" | "password" | "prefs";

export function AccountModal(props: AccountModalProps) {
  const [tab, setTab] = createSignal<Tab>("profile");

  return (
    <Modal open={props.open} onClose={props.onClose} title="账户设置" width="540px">
      <div class="mb-4 flex gap-1 rounded-lg bg-black/[0.03] p-1 dark:bg-white/[0.04]">
        <TabBtn active={tab() === "profile"} onClick={() => setTab("profile")}>
          个人资料
        </TabBtn>
        <TabBtn active={tab() === "password"} onClick={() => setTab("password")}>
          修改密码
        </TabBtn>
        <TabBtn active={tab() === "prefs"} onClick={() => setTab("prefs")}>
          偏好
        </TabBtn>
      </div>
      <Switch fallback={<ProfilePane />}>
        <Match when={tab() === "password"}>
          <PasswordPane />
        </Match>
        <Match when={tab() === "prefs"}>
          <PreferencesPane />
        </Match>
      </Switch>
    </Modal>
  );
}

function TabBtn(props: { active: boolean; onClick: () => void; children: any }) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      class={`flex-1 rounded-md px-3 py-1.5 text-sm font-medium transition-colors
        ${props.active ? "bg-surface text-fg shadow-card" : "text-muted hover:text-fg"}`}
    >
      {props.children}
    </button>
  );
}

function ProfilePane() {
  let fileInput!: HTMLInputElement;
  const [uploading, setUploading] = createSignal(false);
  const [username, setUsername] = createSignal(appState.user?.Username ?? "");
  const [savingName, setSavingName] = createSignal(false);
  const [resending, setResending] = createSignal(false);

  const onPickAvatar = async (e: Event) => {
    const input = e.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    input.value = "";
    if (!file) return;
    setUploading(true);
    try {
      const re = await fileApi.uploadAvatar(file);
      if (re.Id) actions.patchUser({ Logo: re.Id });
      pushToast("头像已更新", "success");
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "头像上传失败", "error");
    } finally {
      setUploading(false);
    }
  };

  const saveName = async () => {
    const name = username().trim();
    if (!name || name === appState.user?.Username) return;
    setSavingName(true);
    try {
      await userApi.updateUsername(name);
      actions.patchUser({ Username: name });
      pushToast("用户名已更新", "success");
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "更新失败", "error");
    } finally {
      setSavingName(false);
    }
  };

  const resend = async () => {
    setResending(true);
    try {
      await userApi.resendActiveEmail();
      pushToast("激活邮件已发送，请查收", "success");
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "发送失败", "error");
    } finally {
      setResending(false);
    }
  };

  return (
    <div class="space-y-5">
      {/* 头像 */}
      <div class="flex items-center gap-4">
        <Avatar src={avatarUrl(appState.user?.Logo)} name={appState.user?.Username} size={64} />
        <div>
          <input ref={fileInput} type="file" accept="image/*" class="hidden" onChange={onPickAvatar} />
          <Button variant="outline" size="sm" disabled={uploading()} onClick={() => fileInput.click()}>
            <Show when={uploading()} fallback={<Upload size={14} />}>
              <Loader2 size={14} class="animate-spin" />
            </Show>
            更换头像
          </Button>
          <p class="mt-1.5 text-xs text-subtle">支持 jpg/png/gif，建议正方形</p>
        </div>
      </div>

      {/* 用户名 */}
      <div>
        <label class="mb-1.5 block text-sm font-medium text-fg">用户名</label>
        <div class="flex gap-2">
          <input
            class="input"
            value={username()}
            onInput={(e) => setUsername(e.currentTarget.value)}
            placeholder="用户名"
          />
          <Button
            variant="primary"
            disabled={savingName() || !username().trim() || username().trim() === appState.user?.Username}
            onClick={() => void saveName()}
          >
            保存
          </Button>
        </div>
      </div>

      {/* 邮箱 */}
      <div>
        <label class="mb-1.5 block text-sm font-medium text-fg">邮箱</label>
        <div class="flex items-center gap-2">
          <input class="input flex-1 opacity-70" value={appState.user?.Email ?? ""} disabled />
          <Show
            when={appState.user?.Verified}
            fallback={
              <Button variant="outline" size="sm" disabled={resending()} onClick={() => void resend()}>
                <AlertCircle size={14} class="text-amber-500" /> 重发激活
              </Button>
            }
          >
            <span class="inline-flex shrink-0 items-center gap-1 rounded-md bg-brand-500/10 px-2 py-1 text-xs font-medium text-brand-600">
              <BadgeCheck size={14} /> 已验证
            </span>
          </Show>
        </div>
      </div>
    </div>
  );
}

function PasswordPane() {
  const [oldPwd, setOldPwd] = createSignal("");
  const [newPwd, setNewPwd] = createSignal("");
  const [confirm, setConfirm] = createSignal("");
  const [saving, setSaving] = createSignal(false);

  const submit = async () => {
    if (!oldPwd() || !newPwd()) {
      pushToast("请填写完整", "error");
      return;
    }
    if (newPwd().length < 6) {
      pushToast("新密码至少 6 位", "error");
      return;
    }
    if (newPwd() !== confirm()) {
      pushToast("两次输入的新密码不一致", "error");
      return;
    }
    setSaving(true);
    try {
      await userApi.updatePwd(oldPwd(), newPwd());
      pushToast("密码已修改", "success");
      setOldPwd("");
      setNewPwd("");
      setConfirm("");
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "修改失败", "error");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div class="space-y-4">
      <div>
        <label class="mb-1.5 block text-sm font-medium text-fg">当前密码</label>
        <input class="input" type="password" value={oldPwd()} onInput={(e) => setOldPwd(e.currentTarget.value)} />
      </div>
      <div>
        <label class="mb-1.5 block text-sm font-medium text-fg">新密码</label>
        <input class="input" type="password" value={newPwd()} onInput={(e) => setNewPwd(e.currentTarget.value)} />
      </div>
      <div>
        <label class="mb-1.5 block text-sm font-medium text-fg">确认新密码</label>
        <input class="input" type="password" value={confirm()} onInput={(e) => setConfirm(e.currentTarget.value)} />
      </div>
      <div class="flex justify-end pt-1">
        <Button variant="primary" disabled={saving()} onClick={() => void submit()}>
          <Show when={saving()}>
            <Loader2 size={14} class="animate-spin" />
          </Show>
          修改密码
        </Button>
      </div>
    </div>
  );
}

function PreferencesPane() {
  // 以「秒」呈现（内部存毫秒）。输入时只更新本地草稿，失焦/回车提交并夹紧。
  const toSec = (ms: number) => Math.round((ms / 1000) * 10) / 10;
  const [secs, setSecs] = createSignal(String(toSec(autoSaveMs())));

  const commit = () => {
    const n = Number(secs());
    if (!Number.isFinite(n)) {
      setSecs(String(toSec(autoSaveMs())));
      return;
    }
    setAutoSaveMs(n * 1000);
    // 回填夹紧后的实际值
    setSecs(String(toSec(autoSaveMs())));
    pushToast("已保存偏好设置", "success");
  };

  const reset = () => {
    setAutoSaveMs(AUTOSAVE_DEFAULT_MS);
    setSecs(String(toSec(autoSaveMs())));
  };

  return (
    <div class="space-y-5">
      <div>
        <label class="mb-1.5 block text-sm font-medium text-fg">自动保存间隔（秒）</label>
        <div class="flex items-center gap-2">
          <input
            class="input w-32"
            type="number"
            min={AUTOSAVE_MIN_MS / 1000}
            max={AUTOSAVE_MAX_MS / 1000}
            step="0.5"
            value={secs()}
            onInput={(e) => setSecs(e.currentTarget.value)}
            onChange={commit}
            onKeyDown={(e) => {
              if (e.key === "Enter") (e.currentTarget as HTMLInputElement).blur();
            }}
          />
          <Button variant="outline" size="sm" onClick={reset}>
            恢复默认
          </Button>
        </div>
        <p class="mt-1.5 text-xs text-subtle">
          编辑笔记停止输入后，间隔多久自动保存一次。范围 {AUTOSAVE_MIN_MS / 1000}–{AUTOSAVE_MAX_MS / 1000} 秒，
          默认 {toSec(AUTOSAVE_DEFAULT_MS)} 秒。切换笔记时仍会立即保存。
        </p>
      </div>
    </div>
  );
}
