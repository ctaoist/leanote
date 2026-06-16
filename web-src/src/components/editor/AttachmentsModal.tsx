import { createSignal, createEffect, on, For, Show } from "solid-js";
import { Upload, Trash2, Download, File as FileIcon } from "lucide-solid";
import { Modal } from "../ui/Modal";
import { CenteredSpinner } from "../ui/Spinner";
import { attachApi } from "../../api/endpoints";
import { formatSize } from "../../lib/format";
import { pushToast } from "../../state/toast";
import type { Attachment, Re } from "../../api/types";

interface AttachmentsModalProps {
  noteId: string;
  open: boolean;
  onClose: () => void;
  onCountChange: (n: number) => void;
}

export function AttachmentsModal(props: AttachmentsModalProps) {
  const [list, setList] = createSignal<Attachment[]>([]);
  const [loading, setLoading] = createSignal(false);
  const [uploading, setUploading] = createSignal(false);
  const [dragOver, setDragOver] = createSignal(false);
  let fileInput: HTMLInputElement | undefined;

  const reload = async () => {
    setLoading(true);
    try {
      const res = await attachApi.list(props.noteId);
      const arr = Array.isArray(res) ? res : [];
      setList(arr);
      props.onCountChange(arr.length);
    } catch {
      setList([]);
    } finally {
      setLoading(false);
    }
  };

  createEffect(
    on(
      () => props.open,
      (open) => {
        if (open) void reload();
      }
    )
  );

  const upload = async (files: FileList | File[]) => {
    const arr = Array.from(files);
    if (!arr.length) return;
    setUploading(true);
    try {
      let failed = 0;
      for (const f of arr) {
        const re = (await attachApi.upload(props.noteId, f)) as Re;
        if (re && re.Ok === false) {
          failed++;
          pushToast(re.Msg || `「${f.name}」上传失败`, "error");
        }
      }
      await reload();
      if (failed < arr.length) pushToast("附件已上传", "success");
    } catch {
      pushToast("上传失败", "error");
    } finally {
      setUploading(false);
    }
  };

  const remove = async (att: Attachment) => {
    if (!confirm(`删除附件「${att.Title || att.Name || ""}」？`)) return;
    try {
      await attachApi.delete(att.AttachId);
      await reload();
    } catch {
      pushToast("删除失败", "error");
    }
  };

  return (
    <Modal open={props.open} onClose={props.onClose} title="附件管理" width="560px">
      {/* 上传区 */}
      <div
        class="mb-4 flex flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed px-4 py-7 text-center transition-colors"
        classList={{
          "border-brand-500 bg-brand-500/5": dragOver(),
          "border-border": !dragOver(),
        }}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          if (e.dataTransfer?.files) void upload(e.dataTransfer.files);
        }}
      >
        <Upload size={22} class="text-subtle" />
        <p class="text-sm text-muted">拖拽文件到此处上传</p>
        <button
          type="button"
          class="btn-outline h-8 px-3 text-xs"
          disabled={uploading()}
          onClick={() => fileInput?.click()}
        >
          {uploading() ? "上传中…" : "选择文件"}
        </button>
        <input
          ref={fileInput}
          type="file"
          multiple
          class="hidden"
          onChange={(e) => {
            const f = e.currentTarget.files;
            if (f) void upload(f);
            e.currentTarget.value = "";
          }}
        />
      </div>

      {/* 附件列表 */}
      <Show
        when={!loading()}
        fallback={
          <div class="py-8">
            <CenteredSpinner label="加载附件…" />
          </div>
        }
      >
        <Show
          when={list().length}
          fallback={<p class="py-6 text-center text-sm text-subtle">暂无附件</p>}
        >
          <ul class="max-h-[42vh] space-y-1 overflow-y-auto">
            <For each={list()}>
              {(att) => (
                <li class="group flex items-center gap-3 rounded-lg px-3 py-2 hover:bg-black/[0.03] dark:hover:bg-white/[0.04]">
                  <FileIcon size={16} class="shrink-0 text-subtle" />
                  <div class="min-w-0 flex-1">
                    <p class="truncate text-sm text-fg">{att.Title || att.Name}</p>
                    <p class="text-xs text-subtle">{formatSize(att.Size)}</p>
                  </div>
                  <a
                    href={attachApi.downloadUrl(att.AttachId)}
                    title="下载"
                    class="flex h-8 w-8 items-center justify-center rounded-md text-muted transition-colors hover:bg-black/5 hover:text-fg dark:hover:bg-white/5"
                  >
                    <Download size={15} />
                  </a>
                  <button
                    type="button"
                    title="删除"
                    onClick={() => void remove(att)}
                    class="flex h-8 w-8 items-center justify-center rounded-md text-muted transition-colors hover:bg-red-500/10 hover:text-red-500"
                  >
                    <Trash2 size={15} />
                  </button>
                </li>
              )}
            </For>
          </ul>
        </Show>
      </Show>
    </Modal>
  );
}
