import { createSignal, Show } from "solid-js";
import { Upload, BadgeCheck, AlertCircle, Loader2 } from "lucide-solid";
import { Modal } from "../ui/Modal";
import { Button } from "../ui/Button";
import { Avatar } from "../ui/Avatar";
import { appState, actions } from "../../state/appStore";
import { userApi, fileApi } from "../../api/endpoints";
import { pushToast } from "../../state/toast";
import { avatarUrl } from "../../lib/url";

interface AccountModalProps {
  open: boolean;
  onClose: () => void;
}

type Tab = "profile" | "password";

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
      </div>
      <Show when={tab() === "profile"} fallback={<PasswordPane />}>
        <ProfilePane />
      </Show>
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
