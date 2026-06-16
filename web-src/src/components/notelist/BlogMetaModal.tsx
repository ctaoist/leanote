import { createEffect, createSignal, Show } from "solid-js";
import { Loader2, ImageIcon } from "lucide-solid";
import { Modal } from "../ui/Modal";
import { Button } from "../ui/Button";
import { ImagePickerModal } from "../album/ImagePickerModal";
import { actions } from "../../state/appStore";
import { pushToast } from "../../state/toast";
import type { Note } from "../../api/types";

/**
 * 编辑一篇博客文章的公开元数据：自定义链接（UrlTitle，留空则用标题）、摘要
 * （文章卡片/列表页摘要）、封面图（ImgSrc，可从图床选择）。保存走
 * `/note/updateBlogMeta`，后端会对 UrlTitle 去重（可能追加 -2）。
 */
export function BlogMetaModal(props: { note: Note; open: boolean; onClose: () => void }) {
  const [urlTitle, setUrlTitle] = createSignal("");
  const [desc, setDesc] = createSignal("");
  const [imgSrc, setImgSrc] = createSignal("");
  const [saving, setSaving] = createSignal(false);
  const [picking, setPicking] = createSignal(false);

  // 每次打开时从当前笔记回填
  createEffect(() => {
    if (props.open) {
      setUrlTitle(props.note.UrlTitle ?? "");
      setDesc(props.note.Desc ?? "");
      setImgSrc(props.note.ImgSrc ?? "");
    }
  });

  const save = async () => {
    setSaving(true);
    try {
      const normalized = await actions.updateBlogMeta(props.note.NoteId, {
        UrlTitle: urlTitle().trim(),
        Desc: desc(),
        ImgSrc: imgSrc().trim(),
      });
      if (normalized && normalized !== urlTitle().trim()) {
        setUrlTitle(normalized);
        pushToast(`链接重复，已调整为「${normalized}」`, "info");
      } else {
        pushToast("博客信息已保存", "success");
      }
      props.onClose();
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "保存失败", "error");
    } finally {
      setSaving(false);
    }
  };

  // ImagePickerModal 回传 markdown `![t](url)`，取出 url 作为封面图
  const onPickCover = (markdown: string) => {
    const m = markdown.match(/\((.*?)\)\s*$/);
    if (m?.[1]) setImgSrc(m[1]);
    setPicking(false);
  };

  return (
    <>
      <Modal open={props.open} onClose={props.onClose} title="博客信息" width="480px">
        <div class="space-y-4">
          <div>
            <label class="mb-1.5 block text-xs text-muted">自定义链接</label>
            <input
              class="input"
              value={urlTitle()}
              onInput={(e) => setUrlTitle(e.currentTarget.value)}
              placeholder="留空则用文章标题"
            />
            <p class="mt-1 text-xs text-muted">用于文章地址 /blog/&lt;用户名&gt;/post/&lt;链接&gt;；重复会自动加后缀。</p>
          </div>

          <div>
            <label class="mb-1.5 block text-xs text-muted">摘要</label>
            <textarea
              class="input min-h-20"
              value={desc()}
              onInput={(e) => setDesc(e.currentTarget.value)}
              placeholder="列表页 / 卡片显示的摘要，留空则自动截取正文"
            />
          </div>

          <div>
            <label class="mb-1.5 block text-xs text-muted">封面图</label>
            <div class="flex gap-2">
              <input
                class="input flex-1"
                value={imgSrc()}
                onInput={(e) => setImgSrc(e.currentTarget.value)}
                placeholder="图片 URL"
              />
              <Button variant="outline" onClick={() => setPicking(true)}>
                <ImageIcon size={15} />
                选图
              </Button>
            </div>
            <Show when={imgSrc().trim()}>
              <img src={imgSrc()} alt="封面预览" class="mt-2 max-h-32 rounded-lg border border-border object-cover" />
            </Show>
          </div>

          <div class="flex justify-end gap-2 pt-1">
            <Button variant="ghost" onClick={props.onClose}>取消</Button>
            <Button variant="primary" disabled={saving()} onClick={() => void save()}>
              <Show when={saving()}>
                <Loader2 size={15} class="animate-spin" />
              </Show>
              保存
            </Button>
          </div>
        </div>
      </Modal>

      <Show when={picking()}>
        <ImagePickerModal open={picking()} onClose={() => setPicking(false)} onPick={onPickCover} />
      </Show>
    </>
  );
}
