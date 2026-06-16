import { createSignal, createEffect, on, For, Show, onCleanup } from "solid-js";
import {
  Plus,
  Trash2,
  Pencil,
  Upload,
  Search,
  Copy,
  Link2,
  ChevronLeft,
  ChevronRight,
  ImageOff,
  Loader2,
  Images,
} from "lucide-solid";
import { Modal } from "../ui/Modal";
import { IconButton } from "../ui/Button";
import { albumApi, fileApi } from "../../api/endpoints";
import { pushToast } from "../../state/toast";
import { formatSize } from "../../lib/format";
import type { Album, FileImage } from "../../api/types";

const PAGE_SIZE = 12;

interface AlbumModalProps {
  open: boolean;
  onClose: () => void;
  /** 选图模式：提供后点击图片回调 Markdown 片段并关闭 */
  onPick?: (markdown: string) => void;
}

async function copyToClipboard(text: string): Promise<void> {
  if (navigator.clipboard?.writeText) return navigator.clipboard.writeText(text);
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  document.execCommand("copy");
  ta.remove();
}

export function AlbumModal(props: AlbumModalProps) {
  let fileInput!: HTMLInputElement;
  const [albums, setAlbums] = createSignal<Album[]>([]);
  const [currentAlbumId, setCurrentAlbumId] = createSignal("");
  const [images, setImages] = createSignal<FileImage[]>([]);
  const [count, setCount] = createSignal(0);
  const [page, setPage] = createSignal(1);
  const [key, setKey] = createSignal("");
  const [loading, setLoading] = createSignal(false);
  const [uploading, setUploading] = createSignal(false);

  const totalPages = () => Math.max(1, Math.ceil(count() / PAGE_SIZE));

  const loadAlbums = async () => {
    try {
      const list = await albumApi.list();
      setAlbums(Array.isArray(list) ? list : []);
    } catch {
      setAlbums([]);
    }
  };

  const reload = async (p = 1) => {
    setPage(p);
    setLoading(true);
    try {
      const re = await fileApi.listImages(currentAlbumId(), p, key(), PAGE_SIZE);
      setImages(Array.isArray(re?.List) ? re.List : []);
      setCount(re?.Count ?? 0);
    } catch (err) {
      setImages([]);
      setCount(0);
      pushToast(err instanceof Error ? err.message : "加载图片失败", "error");
    } finally {
      setLoading(false);
    }
  };

  // 打开时初始化（仅跟踪 open，避免被 reload 内读取的 currentAlbumId/key 误触发）
  createEffect(
    on(
      () => props.open,
      (open) => {
        if (open) {
          void loadAlbums();
          void reload(1);
        }
      }
    )
  );

  const selectAlbum = (id: string) => {
    if (id === currentAlbumId()) return;
    setCurrentAlbumId(id);
    void reload(1);
  };

  // 搜索防抖
  let searchTimer: ReturnType<typeof setTimeout> | undefined;
  const onSearch = (v: string) => {
    setKey(v);
    if (searchTimer) clearTimeout(searchTimer);
    searchTimer = setTimeout(() => void reload(1), 350);
  };
  onCleanup(() => searchTimer && clearTimeout(searchTimer));

  const addAlbum = async () => {
    const name = window.prompt("相册名称")?.trim();
    if (!name) return;
    try {
      const album = await albumApi.add(name);
      if (album && typeof album === "object") {
        await loadAlbums();
        selectAlbum(album.AlbumId);
      } else {
        pushToast("新建相册失败", "error");
      }
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "新建相册失败", "error");
    }
  };

  const renameAlbum = async (album: Album, e: Event) => {
    e.stopPropagation();
    const name = window.prompt("重命名相册", album.Name)?.trim();
    if (!name || name === album.Name) return;
    try {
      await albumApi.update(album.AlbumId, name);
      await loadAlbums();
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "重命名失败", "error");
    }
  };

  const deleteAlbum = async (album: Album, e: Event) => {
    e.stopPropagation();
    if (!confirm(`删除相册「${album.Name}」？相册内图片不会被删除。`)) return;
    try {
      await albumApi.delete(album.AlbumId);
      if (currentAlbumId() === album.AlbumId) setCurrentAlbumId("");
      await loadAlbums();
      void reload(1);
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "删除失败", "error");
    }
  };

  const onUpload = async (e: Event) => {
    const input = e.currentTarget as HTMLInputElement;
    const files = Array.from(input.files ?? []);
    input.value = "";
    if (!files.length) return;
    setUploading(true);
    let ok = 0;
    for (const file of files) {
      try {
        await fileApi.uploadToAlbum(currentAlbumId(), file);
        ok++;
      } catch (err) {
        pushToast(`${file.name}：${err instanceof Error ? err.message : "上传失败"}`, "error");
      }
    }
    setUploading(false);
    if (ok) {
      pushToast(`已上传 ${ok} 张图片`, "success");
      void reload(1);
    }
  };

  const imgUrl = (img: FileImage) => fileApi.imageUrl(img.FileId);
  const markdownOf = (img: FileImage) => `![${img.Title ?? ""}](${imgUrl(img)})`;

  const pick = (img: FileImage) => {
    if (props.onPick) {
      props.onPick(markdownOf(img));
      props.onClose();
    }
  };

  const copyMarkdown = async (img: FileImage, e: Event) => {
    e.stopPropagation();
    await copyToClipboard(markdownOf(img));
    pushToast("已复制 Markdown", "success");
  };
  const copyLink = async (img: FileImage, e: Event) => {
    e.stopPropagation();
    await copyToClipboard(location.origin + imgUrl(img));
    pushToast("已复制链接", "success");
  };
  const renameImage = async (img: FileImage, e: Event) => {
    e.stopPropagation();
    const title = window.prompt("图片标题", img.Title ?? "")?.trim();
    if (title == null || title === (img.Title ?? "")) return;
    try {
      await fileApi.updateImageTitle(img.FileId, title);
      setImages((prev) => prev.map((it) => (it.FileId === img.FileId ? { ...it, Title: title } : it)));
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "改名失败", "error");
    }
  };
  const deleteImage = async (img: FileImage, e: Event) => {
    e.stopPropagation();
    if (!confirm("删除这张图片？")) return;
    try {
      await fileApi.deleteImage(img.FileId);
      void reload(page());
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "删除失败", "error");
    }
  };

  return (
    <Modal open={props.open} onClose={props.onClose} title={props.onPick ? "选择图片" : "图片库"} width="920px">
      <div class="flex h-[560px] gap-4">
        {/* 左：相册列表 */}
        <div class="flex w-48 shrink-0 flex-col">
          <div class="mb-2 flex items-center justify-between">
            <span class="text-xs font-semibold uppercase tracking-wide text-subtle">相册</span>
            <IconButton label="新建相册" onClick={() => void addAlbum()}>
              <Plus size={16} />
            </IconButton>
          </div>
          <div class="min-h-0 flex-1 space-y-0.5 overflow-y-auto">
            <AlbumRow
              active={currentAlbumId() === ""}
              name="全部图片"
              onClick={() => selectAlbum("")}
            />
            <For each={albums()}>
              {(album) => (
                <AlbumRow
                  active={currentAlbumId() === album.AlbumId}
                  name={album.Name}
                  onClick={() => selectAlbum(album.AlbumId)}
                  onRename={(e) => void renameAlbum(album, e)}
                  onDelete={(e) => void deleteAlbum(album, e)}
                />
              )}
            </For>
          </div>
        </div>

        {/* 右：图片网格 */}
        <div class="flex min-w-0 flex-1 flex-col">
          {/* 工具条 */}
          <div class="mb-3 flex items-center gap-2">
            <div class="relative flex-1">
              <Search size={15} class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-subtle" />
              <input
                class="input h-9 pl-9"
                placeholder="搜索图片标题…"
                value={key()}
                onInput={(e) => onSearch(e.currentTarget.value)}
              />
            </div>
            <input ref={fileInput} type="file" accept="image/*" multiple class="hidden" onChange={onUpload} />
            <button class="btn-primary h-9 shrink-0 text-sm" disabled={uploading()} onClick={() => fileInput.click()}>
              <Show when={uploading()} fallback={<Upload size={15} />}>
                <Loader2 size={15} class="animate-spin" />
              </Show>
              上传
            </button>
          </div>

          {/* 网格 */}
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
                    <p class="text-sm">还没有图片，点右上角上传</p>
                  </div>
                }
              >
                <div class="grid grid-cols-4 gap-3">
                  <For each={images()}>
                    {(img) => (
                      <div
                        class={`group relative aspect-square overflow-hidden rounded-lg border border-border bg-bg
                          ${props.onPick ? "cursor-pointer hover:ring-2 hover:ring-brand-500" : ""}`}
                        onClick={() => pick(img)}
                        title={img.Title || img.Name}
                      >
                        <img src={imgUrl(img)} alt={img.Title ?? ""} class="h-full w-full object-cover" loading="lazy" />
                        {/* 悬浮操作 */}
                        <div class="pointer-events-none absolute inset-0 flex flex-col justify-between bg-gradient-to-t from-black/60 via-transparent to-black/30 opacity-0 transition-opacity group-hover:opacity-100">
                          <div class="pointer-events-auto flex justify-end gap-1 p-1.5">
                            <CellBtn label="复制 Markdown" onClick={(e) => void copyMarkdown(img, e)}>
                              <Copy size={13} />
                            </CellBtn>
                            <CellBtn label="复制链接" onClick={(e) => void copyLink(img, e)}>
                              <Link2 size={13} />
                            </CellBtn>
                            <CellBtn label="重命名" onClick={(e) => void renameImage(img, e)}>
                              <Pencil size={13} />
                            </CellBtn>
                            <CellBtn label="删除" danger onClick={(e) => void deleteImage(img, e)}>
                              <Trash2 size={13} />
                            </CellBtn>
                          </div>
                          <div class="px-2 pb-1.5 text-[11px] text-white/90">
                            <div class="truncate">{img.Title || img.Name}</div>
                            <Show when={img.Size}>
                              <div class="text-white/60">{formatSize(img.Size)}</div>
                            </Show>
                          </div>
                        </div>
                      </div>
                    )}
                  </For>
                </div>
              </Show>
            </Show>
          </div>

          {/* 分页 */}
          <Show when={count() > PAGE_SIZE}>
            <div class="mt-3 flex items-center justify-center gap-3 text-sm text-muted">
              <IconButton label="上一页" disabled={page() <= 1} onClick={() => void reload(page() - 1)}>
                <ChevronLeft size={16} />
              </IconButton>
              <span>
                {page()} / {totalPages()}
              </span>
              <IconButton label="下一页" disabled={page() >= totalPages()} onClick={() => void reload(page() + 1)}>
                <ChevronRight size={16} />
              </IconButton>
            </div>
          </Show>
        </div>
      </div>
    </Modal>
  );
}

function AlbumRow(props: {
  active: boolean;
  name: string;
  onClick: () => void;
  onRename?: (e: Event) => void;
  onDelete?: (e: Event) => void;
}) {
  return (
    <div
      onClick={props.onClick}
      class={`group flex cursor-pointer items-center gap-2 rounded-lg px-2.5 py-2 text-sm transition-colors
        ${props.active ? "bg-brand-500/10 text-brand-600" : "text-fg hover:bg-black/[0.04] dark:hover:bg-white/[0.05]"}`}
    >
      <Images size={15} class="shrink-0 opacity-70" />
      <span class="min-w-0 flex-1 truncate">{props.name}</span>
      <Show when={props.onRename}>
        <div class="flex shrink-0 gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
          <button
            class="rounded p-1 text-muted hover:text-fg"
            title="重命名"
            onClick={(e) => props.onRename!(e)}
          >
            <Pencil size={13} />
          </button>
          <button
            class="rounded p-1 text-muted hover:text-red-500"
            title="删除"
            onClick={(e) => props.onDelete!(e)}
          >
            <Trash2 size={13} />
          </button>
        </div>
      </Show>
    </div>
  );
}

function CellBtn(props: { label: string; danger?: boolean; onClick: (e: Event) => void; children: any }) {
  return (
    <button
      type="button"
      title={props.label}
      aria-label={props.label}
      onClick={props.onClick}
      class={`flex h-6 w-6 items-center justify-center rounded-md bg-black/40 text-white backdrop-blur transition-colors
        hover:bg-black/60 ${props.danger ? "hover:bg-red-500/80" : ""}`}
    >
      {props.children}
    </button>
  );
}
