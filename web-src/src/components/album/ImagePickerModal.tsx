import { createSignal, createEffect, on, For, Show } from "solid-js";
import {
  Images,
  ImageOff,
  Loader2,
  Upload,
  ChevronLeft,
  ChevronRight,
  HardDrive,
  Cloud,
  Trash2,
  Plus,
  Pencil,
} from "lucide-solid";
import { Modal } from "../ui/Modal";
import { albumApi, fileApi } from "../../api/endpoints";
import { pushToast } from "../../state/toast";
import { formatSize } from "../../lib/format";
import { getImageBed, uploadToBed } from "../../lib/imageBed";
import type { Album, FileImage, ImageBedConfig } from "../../api/types";

interface Props {
  open: boolean;
  onClose: () => void;
  /** 选图：点击图片回调 Markdown 片段并关闭。 */
  onPick: (markdown: string) => void;
}

type Tab = "browse" | "upload";
// 统一相册模型：local → AlbumId；s3 → 完整 key 前缀（如 "leanote/cats/"）。
type PickAlbum = { id: string; name: string };
type PickImage = { id: string; url: string; title: string; size?: number };

function basename(key: string): string {
  const s = key.replace(/\/+$/, "");
  const i = s.lastIndexOf("/");
  return i >= 0 ? s.slice(i + 1) : s;
}

/**
 * 插入图片用的图片浏览器：S3 模式浏览图床（不同前缀=相册），本地模式浏览相册，
 * 另有「上传」tab。数据源由当前生效的图床配置决定。
 */
export function ImagePickerModal(props: Props) {
  const [bed, setBed] = createSignal<ImageBedConfig | undefined>(undefined);
  const isS3 = () => bed()?.imageBedType === "s3";
  const s3Base = () => (bed()?.s3KeyPrefix ?? "").replace(/^\/+/, "");

  const [tab, setTab] = createSignal<Tab>("browse");
  const [albums, setAlbums] = createSignal<PickAlbum[]>([]);
  const [currentAlbum, setCurrentAlbum] = createSignal<PickAlbum | null>(null);
  const [images, setImages] = createSignal<PickImage[]>([]);
  const [loading, setLoading] = createSignal(false);

  // 分页：每页张数来自图床配置（本地与 s3 共用）。本地按页号（有总数），
  // s3 按 continuation token 翻页（无总数，只能上一页/下一页）。
  const [pageSize, setPageSize] = createSignal(12);
  const [page, setPage] = createSignal(1);
  const [count, setCount] = createSignal(0); // local only
  const [search, setSearch] = createSignal("");
  const [s3Tokens, setS3Tokens] = createSignal<string[]>([]); // s3Tokens[p] = 取第 p 页的 token（第1页=""）
  const [s3HasNext, setS3HasNext] = createSignal(false);

  // 上传 tab 状态
  let fileInput!: HTMLInputElement;
  const [uploadAlbumId, setUploadAlbumId] = createSignal(""); // local: AlbumId
  const [uploadPrefix, setUploadPrefix] = createSignal(""); // s3: 相册名（相对 keyPrefix）
  const [uploading, setUploading] = createSignal(false);

  const totalPages = () => Math.max(1, Math.ceil(count() / pageSize()));

  const loadAlbums = async () => {
    const b = bed();
    if (!b) return;
    try {
      if (b.imageBedType === "s3") {
        const base = s3Base();
        // 大 size 取全部前缀（相册），不受每页张数限制
        const re = await fileApi.bedImages(base, "", 1000);
        setAlbums(
          (re.prefixes ?? []).map((p) => ({ id: p, name: p.slice(base.length).replace(/\/+$/, "") || p }))
        );
      } else {
        const list = await albumApi.list();
        setAlbums((Array.isArray(list) ? list : []).map((a: Album) => ({ id: a.AlbumId, name: a.Name })));
      }
    } catch {
      setAlbums([]);
    }
  };

  const loadImages = async (album: PickAlbum | null, p: number) => {
    const b = bed();
    if (!b) return;
    setLoading(true);
    try {
      if (b.imageBedType === "s3") {
        const prefix = album ? album.id : s3Base();
        const token = s3Tokens()[p] ?? "";
        const re = await fileApi.bedImages(prefix, token, pageSize());
        setImages(
          (re.images ?? []).map((im) => ({ id: im.key, url: im.url, title: basename(im.key), size: im.size }))
        );
        const next = re.next ?? "";
        setS3HasNext(!!next);
        if (next) setS3Tokens((prev) => { const a = [...prev]; a[p + 1] = next; return a; });
      } else {
        const re = await fileApi.listImages(album ? album.id : "", p, search(), pageSize());
        setImages(
          (Array.isArray(re?.List) ? re.List : []).map((f: FileImage) => ({
            id: f.FileId,
            url: fileApi.imageUrl(f.FileId),
            title: f.Title || f.Name || "",
            size: f.Size,
          }))
        );
        setCount(re?.Count ?? 0);
      }
    } catch (err) {
      setImages([]);
      pushToast(err instanceof Error ? err.message : "加载图片失败", "error");
    } finally {
      setLoading(false);
    }
  };

  // 打开时初始化（仅跟踪 open）
  createEffect(
    on(
      () => props.open,
      (open) => {
        if (!open) return;
        void (async () => {
          const b = await getImageBed();
          setBed(b);
          setPageSize(b.imagePageSize && b.imagePageSize > 0 ? b.imagePageSize : 12);
          setTab("browse");
          setCurrentAlbum(null);
          setPage(1);
          setSearch("");
          setS3Tokens([]);
          setS3HasNext(false);
          setUploadAlbumId("");
          setUploadPrefix("");
          await loadAlbums();
          await loadImages(null, 1);
        })();
      }
    )
  );

  const selectAlbum = (album: PickAlbum | null) => {
    setCurrentAlbum(album);
    setPage(1);
    setS3Tokens([]);
    setS3HasNext(false);
    void loadImages(album, 1);
  };

  // 本地搜索防抖（s3 不走后端搜索）
  let searchTimer: ReturnType<typeof setTimeout> | undefined;
  const onSearch = (v: string) => {
    setSearch(v);
    if (searchTimer) clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      setPage(1);
      void loadImages(currentAlbum(), 1);
    }, 350);
  };

  const goPage = (p: number) => {
    if (p < 1) return;
    setPage(p);
    void loadImages(currentAlbum(), p);
  };

  const pick = (img: PickImage) => {
    props.onPick(`![${img.title}](${img.url})`);
    props.onClose();
  };

  // 删除一张图片（本地按 FileId，S3 按 key）。
  const delImage = async (img: PickImage, e: Event) => {
    e.stopPropagation();
    if (!confirm("删除这张图片？")) return;
    try {
      if (isS3()) await fileApi.bedDeleteObject(img.id);
      else await fileApi.deleteImage(img.id);
      await loadImages(currentAlbum(), page());
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "删除失败", "error");
    }
  };

  // S3 相册（前缀）管理。album.id = 完整前缀；album.name = 相对名。
  const createAlbum = async () => {
    const name = window.prompt("新建相册（前缀名）")?.trim();
    if (!name) return;
    try {
      await fileApi.bedCreatePrefix(name);
      await loadAlbums();
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "新建失败", "error");
    }
  };
  const renameAlbum = async (album: PickAlbum) => {
    const newName = window.prompt("重命名相册", album.name)?.trim();
    if (!newName || newName === album.name) return;
    try {
      const re = await fileApi.bedRenamePrefix(album.id, newName);
      pushToast(`已重命名（移动 ${(re as { Item?: { moved?: number } })?.Item?.moved ?? 0} 个对象）`, "success");
      await loadAlbums();
      if (currentAlbum()?.id === album.id) selectAlbum(null);
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "重命名失败", "error");
    }
  };
  const deleteAlbum = async (album: PickAlbum) => {
    if (!confirm(`删除相册「${album.name}」及其中所有图片？此操作无法恢复。`)) return;
    try {
      await fileApi.bedDeletePrefix(album.id);
      await loadAlbums();
      if (currentAlbum()?.id === album.id) selectAlbum(null);
      else void loadImages(currentAlbum(), 1);
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "删除失败", "error");
    }
  };

  const onUpload = async (e: Event) => {
    const input = e.currentTarget as HTMLInputElement;
    const files = Array.from(input.files ?? []);
    input.value = "";
    if (!files.length) return;
    const b = bed();
    if (!b) return;
    setUploading(true);
    let ok = 0;
    for (const file of files) {
      try {
        if (b.imageBedType === "s3") {
          const folder = uploadPrefix().trim().replace(/^\/+|\/+$/g, "");
          const name = folder ? `${folder}/${file.name}` : file.name;
          await uploadToBed(b, name, file);
        } else {
          await fileApi.uploadToAlbum(uploadAlbumId(), file);
        }
        ok++;
      } catch (err) {
        pushToast(`${file.name}：${err instanceof Error ? err.message : "上传失败"}`, "error");
      }
    }
    setUploading(false);
    if (ok) {
      pushToast(`已上传 ${ok} 张图片`, "success");
      setTab("browse");
      await loadAlbums();
      // s3：跳到上传目标相册；本地：跳到目标相册
      if (b.imageBedType === "s3") {
        const folder = uploadPrefix().trim().replace(/^\/+|\/+$/g, "");
        const target = folder ? albums().find((a) => a.name === folder) ?? { id: s3Base() + folder + "/", name: folder } : null;
        selectAlbum(target);
      } else {
        selectAlbum(albums().find((a) => a.id === uploadAlbumId()) ?? null);
      }
    }
  };

  const allLabel = () => (isS3() ? "根目录" : "全部图片");

  return (
    <Modal open={props.open} onClose={props.onClose} title="选择图片" width="920px">
      {/* tab 切换 + 来源标记 */}
      <div class="mb-3 flex items-center gap-2">
        <div class="flex rounded-lg bg-black/[0.04] p-0.5 dark:bg-white/[0.06]">
          <TabBtn active={tab() === "browse"} onClick={() => setTab("browse")}>
            浏览
          </TabBtn>
          <TabBtn active={tab() === "upload"} onClick={() => setTab("upload")}>
            上传
          </TabBtn>
        </div>
        <div class="ml-auto flex items-center gap-1.5 text-xs text-subtle">
          <Show when={isS3()} fallback={<><HardDrive size={13} /> 本地存储</>}>
            <Cloud size={13} /> 网络图床
          </Show>
        </div>
      </div>

      <Show when={tab() === "browse"} fallback={uploadTab()}>
        <div class="flex h-[520px] gap-4">
          {/* 左：相册 */}
          <div class="flex w-48 shrink-0 flex-col">
            <div class="mb-2 flex items-center justify-between">
              <span class="text-xs font-semibold uppercase tracking-wide text-subtle">
                {isS3() ? "相册（前缀）" : "相册"}
              </span>
              <Show when={isS3()}>
                <button
                  type="button"
                  title="新建相册"
                  class="flex h-5 w-5 items-center justify-center rounded text-muted hover:bg-brand-500/10 hover:text-brand-600"
                  onClick={() => void createAlbum()}
                >
                  <Plus size={15} />
                </button>
              </Show>
            </div>
            <div class="min-h-0 flex-1 space-y-0.5 overflow-y-auto">
              <AlbumRow active={currentAlbum() === null} name={allLabel()} onClick={() => selectAlbum(null)} />
              <For each={albums()}>
                {(album) => (
                  <AlbumRow
                    active={currentAlbum()?.id === album.id}
                    name={album.name}
                    onClick={() => selectAlbum(album)}
                    onRename={isS3() ? () => void renameAlbum(album) : undefined}
                    onDelete={isS3() ? () => void deleteAlbum(album) : undefined}
                  />
                )}
              </For>
            </div>
          </div>

          {/* 右：图片网格 */}
          <div class="flex min-w-0 flex-1 flex-col">
            <Show when={!isS3()}>
              <div class="mb-3">
                <input
                  class="input h-9"
                  placeholder="搜索图片标题…"
                  value={search()}
                  onInput={(e) => onSearch(e.currentTarget.value)}
                />
              </div>
            </Show>

            <div class="min-h-0 flex-1 overflow-y-auto">
              <Show
                when={!loading()}
                fallback={
                  <div class="flex h-full items-center justify-center text-subtle">
                    <Loader2 size={22} class="animate-spin" />
                  </div>
                }
              >
                <Show
                  when={images().length}
                  fallback={
                    <div class="flex h-full flex-col items-center justify-center gap-3 text-subtle">
                      <ImageOff size={40} class="opacity-30" />
                      <p class="text-sm">这里还没有图片，去「上传」tab 添加</p>
                    </div>
                  }
                >
                  <div class="grid grid-cols-4 gap-3">
                    <For each={images()}>
                      {(img) => (
                        <div
                          class="group relative aspect-square cursor-pointer overflow-hidden rounded-lg border border-border bg-bg hover:ring-2 hover:ring-brand-500"
                          onClick={() => pick(img)}
                          title={img.title}
                        >
                          <img src={img.url} alt={img.title} class="h-full w-full object-cover" loading="lazy" />
                          <button
                            type="button"
                            title="删除"
                            class="absolute right-1 top-1 z-10 flex h-6 w-6 items-center justify-center rounded-md bg-black/45 text-white opacity-0 backdrop-blur transition-opacity hover:bg-red-500/80 group-hover:opacity-100"
                            onClick={(e) => void delImage(img, e)}
                          >
                            <Trash2 size={13} />
                          </button>
                          <div class="pointer-events-none absolute inset-x-0 bottom-0 bg-gradient-to-t from-black/60 to-transparent px-2 pb-1.5 pt-4 opacity-0 transition-opacity group-hover:opacity-100">
                            <div class="truncate text-[11px] text-white/90">{img.title}</div>
                            <Show when={img.size}>
                              <div class="text-[10px] text-white/60">{formatSize(img.size)}</div>
                            </Show>
                          </div>
                        </div>
                      )}
                    </For>
                  </div>
                </Show>
              </Show>
            </div>

            {/* 分页：本地有总页数；s3 只有上一页/下一页（无总数）。每页张数 admin 配置 */}
            <Show when={isS3() ? page() > 1 || s3HasNext() : count() > pageSize()}>
              <div class="mt-3 flex items-center justify-center gap-3 text-sm text-muted">
                <button
                  class="rounded p-1 disabled:opacity-40"
                  disabled={page() <= 1 || loading()}
                  onClick={() => goPage(page() - 1)}
                >
                  <ChevronLeft size={16} />
                </button>
                <span>
                  <Show when={isS3()} fallback={`${page()} / ${totalPages()}`}>第 {page()} 页</Show>
                </span>
                <button
                  class="rounded p-1 disabled:opacity-40"
                  disabled={(isS3() ? !s3HasNext() : page() >= totalPages()) || loading()}
                  onClick={() => goPage(page() + 1)}
                >
                  <ChevronRight size={16} />
                </button>
              </div>
            </Show>
          </div>
        </div>
      </Show>
    </Modal>
  );

  // 上传 tab（闭包内函数，复用上面的信号）
  function uploadTab() {
    return (
      <div class="flex h-[520px] flex-col items-center justify-center gap-5">
        <div class="w-full max-w-md space-y-4">
          <div>
            <label class="mb-1.5 block text-xs text-muted">目标相册</label>
            <Show
              when={isS3()}
              fallback={
                <select class="input" value={uploadAlbumId()} onChange={(e) => setUploadAlbumId(e.currentTarget.value)}>
                  <option value="">默认相册</option>
                  <For each={albums()}>{(a) => <option value={a.id}>{a.name}</option>}</For>
                </select>
              }
            >
              <input
                class="input"
                list="ipm-prefixes"
                placeholder="留空=根目录；可输入新前缀，如 cats"
                value={uploadPrefix()}
                onInput={(e) => setUploadPrefix(e.currentTarget.value)}
              />
              <datalist id="ipm-prefixes">
                <For each={albums()}>{(a) => <option value={a.name} />}</For>
              </datalist>
            </Show>
          </div>

          <input ref={fileInput} type="file" accept="image/*" multiple class="hidden" onChange={onUpload} />
          <button
            type="button"
            class="flex w-full flex-col items-center gap-2 rounded-xl border-2 border-dashed border-border py-10 text-muted transition-colors hover:border-brand-500/60 hover:text-fg"
            disabled={uploading()}
            onClick={() => fileInput.click()}
          >
            <Show when={uploading()} fallback={<Upload size={26} />}>
              <Loader2 size={26} class="animate-spin" />
            </Show>
            <span class="text-sm">{uploading() ? "上传中…" : "点击选择图片上传"}</span>
            <span class="text-xs text-subtle">
              {isS3() ? "上传到网络图床，保留原文件名" : "上传到本地相册"}
            </span>
          </button>
        </div>
      </div>
    );
  }
}

function TabBtn(props: { active: boolean; onClick: () => void; children: any }) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      class={`rounded-md px-4 py-1 text-sm transition-colors ${
        props.active ? "bg-bg text-fg shadow-sm" : "text-muted hover:text-fg"
      }`}
    >
      {props.children}
    </button>
  );
}

function AlbumRow(props: {
  active: boolean;
  name: string;
  onClick: () => void;
  onRename?: () => void;
  onDelete?: () => void;
}) {
  return (
    <div
      onClick={props.onClick}
      class={`group flex cursor-pointer items-center gap-2 rounded-lg px-2.5 py-2 text-sm transition-colors
        ${props.active ? "bg-brand-500/10 text-brand-600" : "text-fg hover:bg-black/[0.04] dark:hover:bg-white/[0.05]"}`}
    >
      <Images size={15} class="shrink-0 opacity-70" />
      <span class="min-w-0 flex-1 truncate">{props.name}</span>
      <Show when={props.onRename || props.onDelete}>
        <div class="flex shrink-0 gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
          <Show when={props.onRename}>
            <button
              class="rounded p-1 text-muted hover:text-fg"
              title="重命名"
              onClick={(e) => { e.stopPropagation(); props.onRename!(); }}
            >
              <Pencil size={12} />
            </button>
          </Show>
          <Show when={props.onDelete}>
            <button
              class="rounded p-1 text-muted hover:text-red-500"
              title="删除相册"
              onClick={(e) => { e.stopPropagation(); props.onDelete!(); }}
            >
              <Trash2 size={12} />
            </button>
          </Show>
        </div>
      </Show>
    </div>
  );
}
