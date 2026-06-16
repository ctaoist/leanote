import { createEffect, createResource, createSignal, For, Show } from "solid-js";
import { createStore, produce, unwrap } from "solid-js/store";
import { Cloud, HardDrive, Loader2, Plug, Save, Plus, Trash2, Pencil } from "lucide-solid";
import { Button } from "../ui/Button";
import { userApi } from "../../api/endpoints";
import { pushToast } from "../../state/toast";
import { clearImageBedCache } from "../../lib/imageBed";
import { buildKey, s3DeleteObject, s3PutObject, type S3BedConfig } from "../../lib/s3";
import type { ImageBed } from "../../api/types";

const newId = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 10);

function blankBed(seq: number): ImageBed {
  return {
    id: newId(),
    name: `图床 ${seq}`,
    signMode: "client",
    endpoint: "",
    region: "us-east-1",
    bucket: "",
    accessKey: "",
    secretKey: "",
    useSSL: true,
    pathStyle: false,
    publicBaseURL: "",
    keyPrefix: "",
  };
}

/**
 * 用户级图床设置面板：每个登录用户配置自己的图床（本地/S3、多图床切换、每页张数）。
 * 数据走 /user/imageBedSettings 而非 admin 全局设置，因此普通用户也能用。
 */
export function ImageBedPanel() {
  const [settings] = createResource(() => userApi.getImageBedSettings());

  const [imagePageSize, setImagePageSize] = createSignal(12);
  const [saving, setSaving] = createSignal(false);

  // 图片存储 / 图床（多图床）
  const [bedType, setBedType] = createSignal<"local" | "s3">("local");
  const [allowLocal, setAllowLocal] = createSignal(true);
  const [beds, setBeds] = createStore<ImageBed[]>([]);
  const [activeId, setActiveId] = createSignal("");
  const [editingId, setEditingId] = createSignal<string | null>(null);
  const [testingId, setTestingId] = createSignal("");

  // 资源就绪后填充本地可编辑状态
  createEffect(() => {
    const c = settings();
    if (!c) return;
    setImagePageSize(c.imagePageSize || 12);
    setBedType(c.imageBedType ?? "local");
    setAllowLocal(c.allowLocalImageBed !== false);
    const list = Array.isArray(c.imageBeds) ? c.imageBeds : [];
    setBeds(list.map((b) => ({ ...b })));
    setActiveId(c.imageBedActiveId || list[0]?.id || "");
  });

  const addBed = () => {
    const b = blankBed(beds.length + 1);
    setBeds(produce((arr) => arr.push(b)));
    if (!activeId()) setActiveId(b.id);
    setEditingId(b.id);
  };

  const removeBed = (id: string) => {
    setBeds(produce((arr) => {
      const i = arr.findIndex((b) => b.id === id);
      if (i >= 0) arr.splice(i, 1);
    }));
    if (activeId() === id) setActiveId(beds[0]?.id ?? "");
    if (editingId() === id) setEditingId(null);
  };

  const toCfg = (b: ImageBed): S3BedConfig => ({
    endpoint: b.endpoint.trim(),
    region: b.region.trim() || "us-east-1",
    bucket: b.bucket.trim(),
    accessKey: b.accessKey.trim(),
    secretKey: b.secretKey.trim(),
    useSSL: b.useSSL,
    pathStyle: b.pathStyle,
    publicBaseURL: b.publicBaseURL.trim(),
    keyPrefix: b.keyPrefix.trim(),
  });

  const bedComplete = (b: ImageBed) =>
    !!(b.endpoint.trim() && b.bucket.trim() && b.accessKey.trim() && b.secretKey.trim());

  const save = async () => {
    if (!(Number.isInteger(imagePageSize()) && imagePageSize() >= 1)) {
      return pushToast("每页图片数必须为正整数", "error");
    }
    if (bedType() === "local" && !allowLocal()) {
      return pushToast("管理员已禁用本地图床，请选择并配置 S3 图床", "error");
    }
    if (bedType() === "s3") {
      if (!beds.length) return pushToast("请至少配置一个图床", "error");
      const bad = beds.find((b) => !bedComplete(b));
      if (bad) return pushToast(`图床「${bad.name || bad.bucket || "未命名"}」配置不完整`, "error");
    }
    setSaving(true);
    try {
      await userApi.updateImageBedSettings({
        imagePageSize: imagePageSize(),
        imageBedType: bedType(),
        imageBedActiveId: activeId(),
        imageBeds: unwrap(beds).map((b) => ({ ...b })),
      });
      clearImageBedCache();
      pushToast("图床设置已保存", "success");
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "保存失败", "error");
    } finally {
      setSaving(false);
    }
  };

  // 测试连接：上传一张 1px 图再删除，验证桶/CORS/凭证。
  //  - 前端直传模式：浏览器 SigV4 直传（需安全上下文 https/localhost）。
  //  - 后端签名模式：后端预签名 URL + 浏览器普通 PUT/DELETE（http 也可用，无需 Web Crypto）。
  const testConn = async (b: ImageBed) => {
    const cfg = toCfg(b);
    if (!(cfg.endpoint && cfg.bucket && cfg.accessKey && cfg.secretKey)) {
      return pushToast("请填写完整的 S3 配置", "error");
    }
    setTestingId(b.id);
    try {
      if (b.signMode === "server") {
        const clean: ImageBed = {
          ...unwrap(beds).find((x) => x.id === b.id)!,
          endpoint: cfg.endpoint,
          region: cfg.region,
          bucket: cfg.bucket,
          accessKey: cfg.accessKey,
          secretKey: cfg.secretKey,
          useSSL: cfg.useSSL,
          pathStyle: cfg.pathStyle,
          publicBaseURL: cfg.publicBaseURL,
          keyPrefix: cfg.keyPrefix,
        };
        const { putUrl, deleteUrl } = await userApi.presignBedTest(clean);
        const put = await fetch(putUrl, { method: "PUT", body: pngPixel(), headers: { "Content-Type": "image/png" } });
        if (!put.ok) throw new Error(`上传失败 (${put.status})，请检查 桶/CORS/凭证`);
        await fetch(deleteUrl, { method: "DELETE" }).catch(() => undefined);
      } else {
        const key = buildKey(cfg, "__leanote_test__.png");
        await s3PutObject(cfg, key, pngPixel(), "image/png");
        await s3DeleteObject(cfg, key).catch(() => undefined);
      }
      pushToast("连接成功（已上传并清理测试图片）", "success");
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "连接失败", "error");
    } finally {
      setTestingId("");
    }
  };

  return (
    <div class="max-w-2xl">
      <h1 class="mb-1 text-xl font-semibold text-fg">图床设置</h1>
      <p class="mb-6 text-sm text-subtle">配置你自己的图片存储（仅影响你的笔记图片）</p>

      <Show
        when={!settings.loading}
        fallback={
          <div class="flex h-32 items-center justify-center text-muted">
            <Loader2 size={22} class="animate-spin" />
          </div>
        }
      >
        <div class="space-y-5">
          {/* 图片存储 / 图床 */}
          <div class="card p-5">
            <div class="mb-1 font-medium text-fg">图片存储</div>
            <div class="mb-4 text-sm text-muted">
              笔记里粘贴/拖拽/插入的图片存到哪里。切换只影响之后的新图片，已有本地图片不变。
            </div>

            {/* 选择图片浏览器：每页张数（本地与 S3 共用） */}
            <div class="mb-4 flex items-center justify-between gap-4 rounded-lg border border-border px-3.5 py-2.5">
              <div>
                <div class="text-sm font-medium text-fg">每页图片数</div>
                <div class="text-xs text-muted">「插入图片」浏览器每页显示张数，本地与图床共用</div>
              </div>
              <input
                class="input w-24"
                type="number"
                min="1"
                max="100"
                step="1"
                value={imagePageSize()}
                onInput={(e) => setImagePageSize(Math.trunc(Number(e.currentTarget.value)))}
              />
            </div>

            <div class="mb-4 grid grid-cols-2 gap-3">
              <ChoiceCard
                active={bedType() === "local"}
                disabled={!allowLocal()}
                icon={<HardDrive size={18} />}
                title="本地存储"
                desc={allowLocal() ? "存到服务器本地（默认）" : "管理员已禁用"}
                onClick={() => setBedType("local")}
              />
              <ChoiceCard
                active={bedType() === "s3"}
                icon={<Cloud size={18} />}
                title="网络图床（S3）"
                desc="S3 兼容对象存储，可配多个"
                onClick={() => setBedType("s3")}
              />
            </div>

            <Show when={!allowLocal() && bedType() === "local"}>
              <div class="mb-4 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-300">
                管理员已禁用本地图床。请选择「网络图床（S3）」并完成配置后保存；已上传的本地图片不受影响。
              </div>
            </Show>

            <Show when={bedType() === "s3"}>
              <div class="space-y-3 border-t border-border pt-4">
                <div class="flex items-center justify-between">
                  <div class="text-xs font-medium text-muted">
                    图床列表（点左侧圆点设为「当前生效」，新上传用它）
                  </div>
                  <button class="btn-outline h-8 text-sm" onClick={addBed}>
                    <Plus size={15} /> 新增图床
                  </button>
                </div>

                <Show
                  when={beds.length}
                  fallback={<p class="py-4 text-center text-sm text-subtle">还没有图床，点「新增图床」添加</p>}
                >
                  <For each={beds}>
                    {(bed, i) => (
                      <div class="rounded-lg border border-border">
                        {/* 行头 */}
                        <div class="flex items-center gap-3 p-3">
                          <button
                            type="button"
                            title="设为当前生效"
                            aria-pressed={activeId() === bed.id}
                            onClick={() => setActiveId(bed.id)}
                            class={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full border-2 transition-colors
                              ${activeId() === bed.id ? "border-brand-500" : "border-border hover:border-brand-500/60"}`}
                          >
                            <Show when={activeId() === bed.id}>
                              <span class="h-2.5 w-2.5 rounded-full bg-brand-500" />
                            </Show>
                          </button>
                          <div class="min-w-0 flex-1">
                            <div class="flex items-center gap-2">
                              <span class="truncate font-medium text-fg">{bed.name || "未命名图床"}</span>
                              <Show when={activeId() === bed.id}>
                                <span class="rounded bg-brand-500/15 px-1.5 py-0.5 text-[10px] font-medium text-brand-600">
                                  当前
                                </span>
                              </Show>
                            </div>
                            <div class="truncate text-xs text-muted">
                              {bed.bucket || "未配置 bucket"} · {bed.signMode === "server" ? "后端签名" : "前端直传"}
                            </div>
                          </div>
                          <button
                            type="button"
                            title="编辑"
                            class="rounded p-1.5 text-muted hover:bg-black/5 hover:text-fg dark:hover:bg-white/5"
                            onClick={() => setEditingId(editingId() === bed.id ? null : bed.id)}
                          >
                            <Pencil size={15} />
                          </button>
                          <button
                            type="button"
                            title="删除"
                            class="rounded p-1.5 text-muted hover:bg-red-500/10 hover:text-red-500"
                            onClick={() => removeBed(bed.id)}
                          >
                            <Trash2 size={15} />
                          </button>
                        </div>

                        {/* 编辑表单 */}
                        <Show when={editingId() === bed.id}>
                          <div class="space-y-4 border-t border-border p-4">
                            <TextField
                              label="名称"
                              value={bed.name}
                              onChange={(v) => setBeds(i(), "name", v)}
                              placeholder="例如：七牛-华东"
                            />

                            <div>
                              <div class="mb-1.5 text-xs font-medium text-muted">签名方式</div>
                              <div class="grid grid-cols-2 gap-3">
                                <ChoiceCard
                                  active={bed.signMode === "client"}
                                  title="前端直传"
                                  desc="密钥下发浏览器，前端签名"
                                  onClick={() => setBeds(i(), "signMode", "client")}
                                />
                                <ChoiceCard
                                  active={bed.signMode === "server"}
                                  title="后端签名"
                                  desc="密钥留服务器，按次预签名"
                                  onClick={() => setBeds(i(), "signMode", "server")}
                                />
                              </div>
                              <Show when={bed.signMode === "client"}>
                                <p class="mt-2 text-xs text-amber-600 dark:text-amber-400">
                                  前端直传会把 SecretKey 下发到你的浏览器，且需安全上下文（https 或 localhost）。
                                </p>
                              </Show>
                            </div>

                            <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
                              <TextField label="Endpoint（不含协议）" placeholder="s3.amazonaws.com" value={bed.endpoint} onChange={(v) => setBeds(i(), "endpoint", v)} />
                              <TextField label="Region" placeholder="us-east-1" value={bed.region} onChange={(v) => setBeds(i(), "region", v)} />
                              <TextField label="Bucket" value={bed.bucket} onChange={(v) => setBeds(i(), "bucket", v)} />
                              <TextField label="Access Key" value={bed.accessKey} onChange={(v) => setBeds(i(), "accessKey", v)} />
                              <TextField label="Secret Key" value={bed.secretKey} onChange={(v) => setBeds(i(), "secretKey", v)} password />
                              <TextField label="公开访问域名（可选）" placeholder="https://cdn.example.com" value={bed.publicBaseURL} onChange={(v) => setBeds(i(), "publicBaseURL", v)} />
                              <TextField label="Key 前缀（可选）" placeholder="leanote/" value={bed.keyPrefix} onChange={(v) => setBeds(i(), "keyPrefix", v)} />
                            </div>

                            <div class="flex flex-wrap items-center gap-x-6 gap-y-3">
                              <label class="flex items-center gap-2 text-sm text-fg">
                                <Toggle checked={bed.useSSL} onChange={(v) => setBeds(i(), "useSSL", v)} />
                                使用 HTTPS
                              </label>
                              <label class="flex items-center gap-2 text-sm text-fg">
                                <Toggle checked={bed.pathStyle} onChange={(v) => setBeds(i(), "pathStyle", v)} />
                                Path-Style（MinIO/IP 端点需开）
                              </label>
                            </div>

                            <p class="text-xs text-muted">
                              浏览器直传/浏览需在桶上开启 CORS：允许本站 origin 的 <code>GET</code>/<code>PUT</code> 与
                              <code> authorization</code>/<code>x-amz-*</code>/<code>content-type</code> 请求头。
                            </p>

                            <Button variant="outline" disabled={testingId() === bed.id} onClick={() => void testConn(bed)}>
                              <Show when={testingId() === bed.id} fallback={<Plug size={15} />}>
                                <Loader2 size={15} class="animate-spin" />
                              </Show>
                              测试连接
                            </Button>
                          </div>
                        </Show>
                      </div>
                    )}
                  </For>
                </Show>
              </div>
            </Show>
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

function ChoiceCard(props: {
  active: boolean;
  icon?: import("solid-js").JSX.Element;
  title: string;
  desc: string;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      disabled={props.disabled}
      onClick={() => !props.disabled && props.onClick()}
      class={`rounded-lg border p-3 text-left transition-colors ${
        props.disabled
          ? "cursor-not-allowed border-border opacity-50"
          : props.active
            ? "border-brand-500 bg-brand-500/5"
            : "border-border hover:border-brand-500/50"
      }`}
    >
      <div class="flex items-center gap-2 font-medium text-fg">
        {props.icon}
        {props.title}
      </div>
      <div class="mt-0.5 text-xs text-muted">{props.desc}</div>
    </button>
  );
}

function TextField(props: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  password?: boolean;
}) {
  return (
    <div>
      <label class="mb-1.5 block text-xs text-muted">{props.label}</label>
      <input
        class="input"
        type={props.password ? "password" : "text"}
        autocomplete="off"
        placeholder={props.placeholder}
        value={props.value}
        onInput={(e) => props.onChange(e.currentTarget.value)}
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

// 1x1 透明 PNG，用于「测试连接」上传一张极小图片。
function pngPixel(): Blob {
  const b64 =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return new Blob([arr], { type: "image/png" });
}
