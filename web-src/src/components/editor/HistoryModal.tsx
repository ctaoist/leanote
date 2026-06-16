import { createSignal, createEffect, on, For, Show } from "solid-js";
import { RotateCcw, History as HistoryIcon } from "lucide-solid";
import { Modal } from "../ui/Modal";
import { Button } from "../ui/Button";
import { CenteredSpinner } from "../ui/Spinner";
import { noteHistoryApi } from "../../api/endpoints";
import { renderMarkdown } from "../../lib/markdown";
import { formatDateTime } from "../../lib/format";
import type { NoteHistory } from "../../api/types";

interface HistoryModalProps {
  noteId: string;
  isMarkdown: boolean;
  open: boolean;
  onClose: () => void;
  onRestore: (content: string) => void;
}

export function HistoryModal(props: HistoryModalProps) {
  const [list, setList] = createSignal<NoteHistory[]>([]);
  const [loading, setLoading] = createSignal(false);
  const [selected, setSelected] = createSignal(0);

  // 打开时拉取历史；空 / 非数组按「暂无历史」处理。
  createEffect(
    on(
      () => props.open,
      async (open) => {
        if (!open) return;
        setLoading(true);
        setSelected(0);
        try {
          const res = await noteHistoryApi.list(props.noteId);
          setList(Array.isArray(res) ? res : []);
        } catch {
          setList([]);
        } finally {
          setLoading(false);
        }
      }
    )
  );

  const current = () => list()[selected()];
  const previewHtml = () => {
    const c = current()?.Content ?? "";
    return props.isMarkdown ? renderMarkdown(c) : c;
  };

  const restore = () => {
    const c = current();
    if (!c) return;
    props.onRestore(c.Content);
    props.onClose();
  };

  return (
    <Modal open={props.open} onClose={props.onClose} title="历史版本" width="880px">
      <Show
        when={!loading()}
        fallback={
          <div class="py-20">
            <CenteredSpinner label="加载历史…" />
          </div>
        }
      >
        <Show when={list().length} fallback={<EmptyHistory />}>
          <div class="flex h-[62vh] gap-4">
            {/* 版本列表 */}
            <div class="w-52 shrink-0 space-y-0.5 overflow-y-auto border-r border-border pr-2">
              <For each={list()}>
                {(h, i) => (
                  <button
                    type="button"
                    onClick={() => setSelected(i())}
                    class="flex w-full flex-col items-start gap-0.5 rounded-lg px-3 py-2 text-left transition-colors"
                    classList={{
                      "bg-brand-500/10 text-brand-600": selected() === i(),
                      "text-muted hover:bg-black/5 dark:hover:bg-white/5": selected() !== i(),
                    }}
                  >
                    <span class="text-sm font-medium">版本 #{list().length - i()}</span>
                    <span class="text-xs text-subtle">{formatDateTime(h.UpdatedTime)}</span>
                  </button>
                )}
              </For>
            </div>

            {/* 预览 + 恢复 */}
            <div class="flex min-w-0 flex-1 flex-col">
              <div class="mb-2 flex shrink-0 items-center justify-between">
                <span class="text-xs text-subtle">{formatDateTime(current()?.UpdatedTime)}</span>
                <Button size="sm" variant="outline" onClick={restore}>
                  <RotateCcw size={14} /> 恢复此版本
                </Button>
              </div>
              <div class="min-h-0 flex-1 overflow-y-auto rounded-lg border border-border bg-bg px-4 py-3">
                <div class="prose prose-sm dark:prose-invert max-w-none" innerHTML={previewHtml()} />
              </div>
            </div>
          </div>
        </Show>
      </Show>
    </Modal>
  );
}

function EmptyHistory() {
  return (
    <div class="flex flex-col items-center justify-center gap-3 py-20 text-center text-subtle">
      <HistoryIcon size={40} class="opacity-30" />
      <p class="text-sm">这篇笔记暂无历史版本</p>
      <p class="text-xs">编辑保存若干次后，旧版本会出现在这里</p>
    </div>
  );
}
