import { createEffect, createResource, createSignal, Show } from "solid-js";
import { Loader2, Save } from "lucide-solid";
import { Button } from "../ui/Button";
import { adminApi } from "../../api/endpoints";
import { pushToast } from "../../state/toast";

/**
 * 管理员专属「全局设置」：开放注册 + 上传大小限制（站点级，对所有用户生效）。
 * 图床改为用户级后已移出本面板，见 ImageBedPanel（所有用户可用）。
 */
export function SettingsPanel() {
  const [configs] = createResource(() => adminApi.getConfigs());

  const [openRegister, setOpenRegister] = createSignal(true);
  const [allowLocalBed, setAllowLocalBed] = createSignal(true);
  const [imageSize, setImageSize] = createSignal(2);
  const [attachSize, setAttachSize] = createSignal(5);
  const [avatarSize, setAvatarSize] = createSignal(1);
  const [saving, setSaving] = createSignal(false);

  // 资源就绪后填充本地可编辑状态
  createEffect(() => {
    const c = configs();
    if (!c) return;
    setOpenRegister(c.openRegister);
    setAllowLocalBed(c.allowLocalImageBed);
    setImageSize(c.uploadImageSize);
    setAttachSize(c.uploadAttachSize);
    setAvatarSize(c.uploadAvatarSize);
  });

  const save = async () => {
    if ([imageSize(), attachSize(), avatarSize()].some((n) => !(n > 0))) {
      return pushToast("上传大小必须为正数", "error");
    }
    setSaving(true);
    try {
      await adminApi.updateConfigs({
        openRegister: openRegister(),
        allowLocalImageBed: allowLocalBed(),
        uploadImageSize: imageSize(),
        uploadAttachSize: attachSize(),
        uploadAvatarSize: avatarSize(),
      });
      pushToast("设置已保存", "success");
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "保存失败", "error");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div class="max-w-2xl">
      <h1 class="mb-1 text-xl font-semibold text-fg">全局设置</h1>
      <p class="mb-6 text-sm text-subtle">影响所有用户的站点级配置</p>

      <Show
        when={!configs.loading}
        fallback={
          <div class="flex h-32 items-center justify-center text-muted">
            <Loader2 size={22} class="animate-spin" />
          </div>
        }
      >
        <div class="space-y-5">
          {/* 开放注册 */}
          <div class="card flex items-center justify-between gap-4 p-5">
            <div>
              <div class="font-medium text-fg">开放注册</div>
              <div class="text-sm text-muted">关闭后，访客将无法通过注册页自助注册</div>
            </div>
            <Toggle checked={openRegister()} onChange={setOpenRegister} />
          </div>

          {/* 允许本地图床 */}
          <div class="card flex items-center justify-between gap-4 p-5">
            <div>
              <div class="font-medium text-fg">允许本地图床</div>
              <div class="text-sm text-muted">
                关闭后，用户不能再把图床设为「本地存储」，只能使用 S3（已上传的本地图片不受影响）
              </div>
            </div>
            <Toggle checked={allowLocalBed()} onChange={setAllowLocalBed} />
          </div>

          {/* 上传大小限制 */}
          <div class="card p-5">
            <div class="mb-4 font-medium text-fg">上传大小限制（MB）</div>
            <div class="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <SizeField label="图片" value={imageSize()} onChange={setImageSize} />
              <SizeField label="附件" value={attachSize()} onChange={setAttachSize} />
              <SizeField label="头像" value={avatarSize()} onChange={setAvatarSize} />
            </div>
          </div>

          <div class="flex justify-end">
            <Button variant="primary" disabled={saving()} onClick={() => void save()}>
              <Show when={saving()} fallback={<Save size={15} />}>
                <Loader2 size={15} class="animate-spin" />
              </Show>
              保存设置
            </Button>
          </div>
        </div>
      </Show>
    </div>
  );
}

function SizeField(props: { label: string; value: number; onChange: (n: number) => void }) {
  return (
    <div>
      <label class="mb-1.5 block text-xs text-muted">{props.label}</label>
      <input
        class="input"
        type="number"
        min="0.1"
        step="0.5"
        value={props.value}
        onInput={(e) => props.onChange(Number(e.currentTarget.value))}
      />
    </div>
  );
}

function Toggle(props: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={props.checked}
      onClick={() => props.onChange(!props.checked)}
      class={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors
        ${props.checked ? "bg-brand-500" : "bg-black/15 dark:bg-white/20"}`}
    >
      <span
        class={`inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform
          ${props.checked ? "translate-x-[22px]" : "translate-x-0.5"}`}
      />
    </button>
  );
}
