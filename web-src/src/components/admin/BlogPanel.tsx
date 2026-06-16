import { createEffect, createResource, createSignal, For, Show } from "solid-js";
import { Loader2, Save, Star, Trash2, Pencil, Download, Upload, FilePlus2, Image as ImageIcon, Globe, Rocket, ExternalLink, Eye } from "lucide-solid";
import { Button } from "../ui/Button";
import { Modal } from "../ui/Modal";
import { blogApi } from "../../api/endpoints";
import { pushToast } from "../../state/toast";
import { appState } from "../../state/appStore";
import { ThemeCodeEditor } from "./ThemeCodeEditor";
import type { BlogTheme } from "../../api/types";

const SORT_FIELDS: { value: string; label: string }[] = [
  { value: "PublicTime", label: "发布时间" },
  { value: "CreatedTime", label: "创建时间" },
  { value: "UpdatedTime", label: "更新时间" },
  { value: "Title", label: "标题" },
  { value: "ReadNum", label: "阅读数" },
  { value: "LikeNum", label: "点赞数" },
];

/**
 * 用户级博客设置面板（所有登录用户可用）：基本信息 / 评论 / 分页排序 + 主题
 * （选择 / 编辑 / 导入 / 导出）。数据走 /user/blog* 与 /user/theme*，存于现有
 * user_blogs 与 themes 集合（drop-in）。本项目暂无公开博客渲染器，故为「存储+编辑」。
 */
export function BlogPanel() {
  const [settings] = createResource(() => blogApi.getSettings());
  const [themes, { refetch: refetchThemes }] = createResource(() => blogApi.listThemes());

  const [title, setTitle] = createSignal("");
  const [subTitle, setSubTitle] = createSignal("");
  const [aboutMe, setAboutMe] = createSignal("");
  const [canComment, setCanComment] = createSignal(false);
  const [commentType, setCommentType] = createSignal<"default" | "disqus">("default");
  const [disqusId, setDisqusId] = createSignal("");
  const [perPageSize, setPerPageSize] = createSignal(10);
  const [sortField, setSortField] = createSignal("PublicTime");
  const [isAsc, setIsAsc] = createSignal(false);
  const [blogType, setBlogType] = createSignal<"dynamic" | "static">("dynamic");
  const [subDomain, setSubDomain] = createSignal("");
  const [domain, setDomain] = createSignal("");
  const [baseDomain, setBaseDomain] = createSignal("");
  const [saving, setSaving] = createSignal(false);

  const [editing, setEditing] = createSignal<BlogTheme | null>(null);
  const [importing, setImporting] = createSignal(false);
  const [busyId, setBusyId] = createSignal("");

  const origin = () => (typeof window !== "undefined" ? window.location.origin : "");

  createEffect(() => {
    const c = settings();
    if (!c) return;
    setTitle(c.Title ?? "");
    setSubTitle(c.SubTitle ?? "");
    setAboutMe(c.AboutMe ?? "");
    setCanComment(!!c.CanComment);
    setCommentType(c.CommentType === "disqus" ? "disqus" : "default");
    setDisqusId(c.DisqusId ?? "");
    setPerPageSize(c.PerPageSize || 10);
    setSortField(c.SortField || "PublicTime");
    setIsAsc(!!c.IsAsc);
    setBlogType(c.BlogType === "static" ? "static" : "dynamic");
    setSubDomain(c.SubDomain ?? "");
    setDomain(c.Domain ?? "");
    setBaseDomain(c.BlogBaseDomain ?? "");
  });

  const save = async () => {
    if (!title().trim()) return pushToast("请填写博客标题", "error");
    if (!(Number.isInteger(perPageSize()) && perPageSize() >= 1)) {
      return pushToast("每页篇数必须为正整数", "error");
    }
    setSaving(true);
    try {
      await blogApi.updateSettings({
        Title: title().trim(),
        SubTitle: subTitle().trim(),
        AboutMe: aboutMe(),
        CanComment: canComment(),
        CommentType: commentType(),
        DisqusId: disqusId().trim(),
        PerPageSize: perPageSize(),
        SortField: sortField(),
        IsAsc: isAsc(),
        BlogType: blogType(),
        SubDomain: subDomain().trim().toLowerCase(),
        Domain: domain().trim().toLowerCase(),
      });
      pushToast("博客设置已保存", "success");
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "保存失败", "error");
    } finally {
      setSaving(false);
    }
  };

  const onActive = async (t: BlogTheme) => {
    setBusyId(t.ThemeId);
    try {
      await blogApi.activeTheme(t.ThemeId);
      await refetchThemes();
      pushToast(`已切换主题：${t.Name}`, "success");
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "切换失败", "error");
    } finally {
      setBusyId("");
    }
  };

  const onDelete = async (t: BlogTheme) => {
    if (t.IsActive) return pushToast("当前使用中的主题不可删除", "error");
    if (!window.confirm(`确定删除主题「${t.Name}」？此操作会删除其全部文件。`)) return;
    setBusyId(t.ThemeId);
    try {
      await blogApi.deleteTheme(t.ThemeId);
      await refetchThemes();
      pushToast("主题已删除", "success");
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "删除失败", "error");
    } finally {
      setBusyId("");
    }
  };

  const onImport = async (e: Event) => {
    const input = e.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    input.value = "";
    if (!file) return;
    setImporting(true);
    try {
      const re = await blogApi.importTheme(file);
      await refetchThemes();
      pushToast(`已导入主题：${re.Item?.name ?? ""}`, "success");
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "导入失败", "error");
    } finally {
      setImporting(false);
    }
  };

  return (
    <div class="max-w-2xl">
      <div class="mb-6 flex items-start justify-between gap-4">
        <div>
          <h1 class="mb-1 text-xl font-semibold text-fg">博客设置</h1>
          <p class="text-sm text-subtle">你自己的博客信息、发布方式、评论、分页与主题（仅影响你的博客）</p>
        </div>
        <Button variant="outline" onClick={() => window.open(blogApi.previewUrl(), "_blank")}>
          <Eye size={15} />
          预览博客
        </Button>
      </div>

      <Show
        when={!settings.loading}
        fallback={
          <div class="flex h-32 items-center justify-center text-muted">
            <Loader2 size={22} class="animate-spin" />
          </div>
        }
      >
        <div class="space-y-5">
          {/* 基本信息 */}
          <div class="card p-5">
            <div class="mb-4 font-medium text-fg">基本信息</div>
            <div class="space-y-4">
              <Field label="标题">
                <input class="input" value={title()} onInput={(e) => setTitle(e.currentTarget.value)} placeholder="eg: leanote's blog" />
              </Field>
              <Field label="副标题">
                <input class="input" value={subTitle()} onInput={(e) => setSubTitle(e.currentTarget.value)} placeholder="eg: Not Just A Notebook" />
              </Field>
              <Field label="关于我">
                <textarea class="input min-h-20" value={aboutMe()} onInput={(e) => setAboutMe(e.currentTarget.value)} />
              </Field>
              <p class="text-xs text-muted">Logo / 头像由主题管理（见下方「主题」）。</p>
            </div>
          </div>

          {/* 发布方式 */}
          <div class="card p-5">
            <div class="mb-4 font-medium text-fg">发布方式</div>
            <div class="flex flex-col gap-3 sm:flex-row">
              <ModeCard
                active={blogType() === "dynamic"}
                title="动态博客"
                desc="本服务器实时渲染，访问 /blog/你的用户名 即可。改完即生效，无需部署。"
                onClick={() => setBlogType("dynamic")}
              />
              <ModeCard
                active={blogType() === "static"}
                title="静态博客"
                desc="生成静态 HTML 并一键部署到 GitHub Pages（或下载 zip 自行部署）。"
                onClick={() => setBlogType("static")}
              />
            </div>
            <p class="mt-3 text-xs text-muted">
              切换后点下方「保存设置」生效。动态模式下静态站点链接不可用；静态模式下 /blog/你的用户名 会提示跳转到已部署站点。
            </p>

            <Show when={blogType() === "dynamic"}>
              <div class="mt-4 flex items-center gap-3 border-t border-border pt-4 text-sm">
                <Globe size={16} class="shrink-0 text-muted" />
                <Show when={appState.user?.Username} fallback={<span class="text-muted">登录后可见公开地址</span>}>
                  <code class="truncate rounded bg-black/5 px-2 py-1 text-xs dark:bg-white/10">
                    {origin()}/blog/{appState.user?.Username}
                  </code>
                  <a
                    class="ml-auto inline-flex items-center gap-1 text-brand-600 hover:underline"
                    href={`/blog/${appState.user?.Username}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    访问 <ExternalLink size={13} />
                  </a>
                </Show>
              </div>

              {/* 自定义域名：子域名 + 独立域名（在根路径打开本博客，不带 /blog 前缀） */}
              <div class="mt-4 space-y-4 border-t border-border pt-4">
                <Field label="子域名">
                  <input
                    class="input"
                    value={subDomain()}
                    onInput={(e) => setSubDomain(e.currentTarget.value)}
                    placeholder="eg: myblog"
                  />
                  <Show when={subDomain().trim()}>
                    <p class="mt-1 text-xs text-muted">
                      <Show when={baseDomain()} fallback="管理员尚未配置子域名基础域名，此项暂不生效">
                        访问地址：
                        <code class="rounded bg-black/5 px-1 dark:bg-white/10">
                          https://{subDomain().trim().toLowerCase()}.{baseDomain()}
                        </code>
                      </Show>
                    </p>
                  </Show>
                </Field>
                <Field label="独立域名">
                  <input
                    class="input"
                    value={domain()}
                    onInput={(e) => setDomain(e.currentTarget.value)}
                    placeholder="eg: blog.example.com"
                  />
                  <p class="mt-1 text-xs text-muted">
                    把该域名 CNAME 解析到本站后，
                    <Show when={domain().trim()} fallback="访问它即可在根路径打开本博客。">
                      访问{" "}
                      <code class="rounded bg-black/5 px-1 dark:bg-white/10">
                        https://{domain().trim().toLowerCase()}
                      </code>{" "}
                      即可在根路径打开本博客。
                    </Show>
                  </p>
                </Field>
              </div>
            </Show>
          </div>

          <Show when={blogType() === "static"}>
            <DeployCard />
          </Show>

          {/* 评论 */}
          <div class="card p-5">
            <div class="mb-4 font-medium text-fg">评论</div>
            <label class="flex items-center gap-2 text-sm text-fg">
              <Toggle checked={canComment()} onChange={setCanComment} />
              开启评论
            </label>
            <Show when={canComment()}>
              <div class="mt-4 space-y-3 border-t border-border pt-4">
                <div class="flex gap-6">
                  <label class="flex items-center gap-2 text-sm text-fg">
                    <input type="radio" name="commentType" checked={commentType() === "default"} onChange={() => setCommentType("default")} />
                    默认评论
                  </label>
                  <label class="flex items-center gap-2 text-sm text-fg">
                    <input type="radio" name="commentType" checked={commentType() === "disqus"} onChange={() => setCommentType("disqus")} />
                    Disqus
                  </label>
                </div>
                <Show when={commentType() === "disqus"}>
                  <Field label="Disqus Id">
                    <input class="input" value={disqusId()} onInput={(e) => setDisqusId(e.currentTarget.value)} placeholder="eg: leanote" />
                  </Field>
                </Show>
              </div>
            </Show>
          </div>

          {/* 分页与排序 */}
          <div class="card p-5">
            <div class="mb-4 font-medium text-fg">分页与排序</div>
            <div class="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <Field label="每页篇数">
                <input class="input" type="number" min="1" step="1" value={perPageSize()} onInput={(e) => setPerPageSize(Math.trunc(Number(e.currentTarget.value)))} />
              </Field>
              <Field label="排序字段">
                <select class="input" value={sortField()} onChange={(e) => setSortField(e.currentTarget.value)}>
                  <For each={SORT_FIELDS}>{(f) => <option value={f.value}>{f.label}</option>}</For>
                </select>
              </Field>
              <Field label="升序">
                <label class="flex h-9 items-center gap-2 text-sm text-fg">
                  <Toggle checked={isAsc()} onChange={setIsAsc} />
                  {isAsc() ? "升序" : "降序"}
                </label>
              </Field>
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

          {/* 主题 */}
          <div class="card p-5">
            <div class="mb-1 flex items-center justify-between gap-4">
              <div class="font-medium text-fg">主题</div>
              <label class="btn-outline h-8 cursor-pointer text-sm">
                <Show when={importing()} fallback={<Upload size={15} />}>
                  <Loader2 size={15} class="animate-spin" />
                </Show>
                导入主题(.zip)
                <input type="file" accept=".zip" class="hidden" onChange={(e) => void onImport(e)} />
              </label>
            </div>
            <div class="mb-4 text-sm text-muted">
              主题以文件夹形式存储，决定博客的外观与排版。新主题通过「导入」获得，可在线编辑。
            </div>

            <Show
              when={(themes() ?? []).length}
              fallback={<p class="py-4 text-center text-sm text-subtle">还没有主题，点「导入主题(.zip)」添加</p>}
            >
              <div class="space-y-2">
                <For each={themes()}>
                  {(t) => (
                    <div class="flex items-center gap-3 rounded-lg border border-border p-3">
                      <div class="min-w-0 flex-1">
                        <div class="flex items-center gap-2">
                          <span class="truncate font-medium text-fg">{t.Name || "未命名主题"}</span>
                          <Show when={t.IsActive}>
                            <span class="rounded bg-brand-500/15 px-1.5 py-0.5 text-[10px] font-medium text-brand-600">当前</span>
                          </Show>
                        </div>
                        <div class="truncate text-xs text-muted">
                          {t.Author ? `By ${t.Author}` : "—"}{t.Version ? ` · v${t.Version}` : ""}
                        </div>
                      </div>
                      <Show when={!t.IsActive}>
                        <IconBtn title="设为当前" disabled={busyId() === t.ThemeId} onClick={() => void onActive(t)}>
                          <Star size={15} />
                        </IconBtn>
                      </Show>
                      <IconBtn title="编辑" onClick={() => setEditing(t)}>
                        <Pencil size={15} />
                      </IconBtn>
                      <IconBtn title="导出(.zip)" onClick={() => window.open(blogApi.exportThemeUrl(t.ThemeId))}>
                        <Download size={15} />
                      </IconBtn>
                      <Show when={!t.IsActive}>
                        <IconBtn title="删除" danger disabled={busyId() === t.ThemeId} onClick={() => void onDelete(t)}>
                          <Trash2 size={15} />
                        </IconBtn>
                      </Show>
                    </div>
                  )}
                </For>
              </div>
            </Show>
          </div>
        </div>
      </Show>

      <Show when={editing()}>
        {(t) => <ThemeEditorModal theme={t()} onClose={() => setEditing(null)} />}
      </Show>
    </div>
  );
}

/** 主题文件编辑器：左侧文件列表 + 右侧等宽文本编辑 + 新建/删除文件 + 图片上传。 */
function ThemeEditorModal(props: { theme: BlogTheme; onClose: () => void }) {
  const themeId = props.theme.ThemeId;
  const [files, { refetch: refetchFiles }] = createResource(() => blogApi.listThemeFiles(themeId));
  const [current, setCurrent] = createSignal("");
  const [content, setContent] = createSignal("");
  const [loading, setLoading] = createSignal(false);
  const [saving, setSaving] = createSignal(false);
  const [uploading, setUploading] = createSignal(false);

  // 首次拿到文件列表时，自动打开第一个
  createEffect(() => {
    const list = files();
    if (list && list.length && !current()) void openFile(list[0]);
  });

  const openFile = async (name: string) => {
    setCurrent(name);
    setLoading(true);
    try {
      setContent(await blogApi.getThemeFile(themeId, name));
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "读取失败", "error");
    } finally {
      setLoading(false);
    }
  };

  const save = async () => {
    if (!current()) return;
    setSaving(true);
    try {
      await blogApi.updateThemeFile(themeId, current(), content());
      pushToast("已保存", "success");
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "保存失败", "error");
    } finally {
      setSaving(false);
    }
  };

  const newFile = async () => {
    const name = window.prompt("新文件名（相对主题目录，如 partials/x.html）");
    if (!name) return;
    setCurrent(name.trim());
    setContent("");
  };

  const deleteFile = async (name: string) => {
    if (!window.confirm(`删除文件 ${name}？`)) return;
    try {
      await blogApi.deleteThemeFile(themeId, name);
      await refetchFiles();
      if (current() === name) {
        setCurrent("");
        setContent("");
      }
      pushToast("已删除", "success");
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "删除失败", "error");
    }
  };

  const uploadImage = async (e: Event) => {
    const input = e.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    input.value = "";
    if (!file) return;
    setUploading(true);
    try {
      await blogApi.uploadThemeImage(themeId, file);
      await refetchFiles();
      pushToast("图片已上传到 images/", "success");
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "上传失败", "error");
    } finally {
      setUploading(false);
    }
  };

  return (
    <Modal open onClose={props.onClose} title={`编辑主题 · ${props.theme.Name}`} width="960px">
      <div class="flex h-[68vh] gap-3">
        {/* 文件列表 */}
        <div class="flex w-56 shrink-0 flex-col rounded-lg border border-border">
          <div class="flex items-center justify-between border-b border-border px-2 py-1.5">
            <span class="text-xs font-medium text-muted">文件</span>
            <button class="rounded p-1 text-muted hover:bg-black/5 hover:text-fg dark:hover:bg-white/5" title="新建文件" onClick={() => void newFile()}>
              <FilePlus2 size={15} />
            </button>
          </div>
          <div class="min-h-0 flex-1 overflow-y-auto p-1">
            <Show when={!files.loading} fallback={<div class="p-3 text-center text-muted"><Loader2 size={16} class="animate-spin" /></div>}>
              <For each={files()}>
                {(f) => (
                  <div
                    class={`group flex items-center gap-1 rounded px-2 py-1 text-sm ${
                      current() === f ? "bg-brand-500/10 text-brand-600" : "text-fg hover:bg-black/5 dark:hover:bg-white/5"
                    }`}
                  >
                    <button class="min-w-0 flex-1 truncate text-left font-mono text-xs" onClick={() => void openFile(f)} title={f}>
                      {f}
                    </button>
                    <button class="hidden rounded p-0.5 text-muted hover:text-red-500 group-hover:block" title="删除" onClick={() => void deleteFile(f)}>
                      <Trash2 size={13} />
                    </button>
                  </div>
                )}
              </For>
            </Show>
          </div>
          <div class="border-t border-border p-1.5">
            <label class="btn-outline h-8 w-full cursor-pointer justify-center text-xs">
              <Show when={uploading()} fallback={<ImageIcon size={14} />}>
                <Loader2 size={14} class="animate-spin" />
              </Show>
              上传图片
              <input type="file" accept="image/*" class="hidden" onChange={(e) => void uploadImage(e)} />
            </label>
          </div>
        </div>

        {/* 编辑区 */}
        <div class="flex min-w-0 flex-1 flex-col">
          <div class="mb-2 flex items-center justify-between gap-2">
            <span class="truncate font-mono text-xs text-muted">{current() || "未选择文件"}</span>
            <Button variant="primary" disabled={saving() || !current()} onClick={() => void save()}>
              <Show when={saving()} fallback={<Save size={14} />}>
                <Loader2 size={14} class="animate-spin" />
              </Show>
              保存
            </Button>
          </div>
          <div class="min-h-0 flex-1 overflow-hidden rounded-lg border border-border bg-bg">
            <Show
              when={current()}
              fallback={
                <div class="flex h-full items-center justify-center text-sm text-subtle">
                  从左侧选择一个文件进行编辑
                </div>
              }
            >
              <ThemeCodeEditor
                value={content()}
                filename={current()}
                editable={!loading()}
                onChange={setContent}
              />
            </Show>
          </div>
        </div>
      </div>
    </Modal>
  );
}

/** 发布方式选择卡（动态 / 静态）。 */
function ModeCard(props: { active: boolean; title: string; desc: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      class={`flex-1 rounded-lg border p-4 text-left transition-colors ${
        props.active ? "border-brand-500 bg-brand-500/5 ring-1 ring-brand-500" : "border-border hover:bg-black/5 dark:hover:bg-white/5"
      }`}
    >
      <div class="flex items-center gap-2">
        <span class={`h-3.5 w-3.5 rounded-full border-2 ${props.active ? "border-brand-500 bg-brand-500" : "border-muted"}`} />
        <span class="font-medium text-fg">{props.title}</span>
      </div>
      <p class="mt-1.5 text-xs text-muted">{props.desc}</p>
    </button>
  );
}

/** 静态博客的 GitHub Pages 部署卡（仓库/分支/域名/路径/Token + 保存/生成部署/下载 zip）。 */
function DeployCard() {
  const [cfg, { refetch }] = createResource(() => blogApi.getDeploySettings());
  const [repo, setRepo] = createSignal("");
  const [branch, setBranch] = createSignal("gh-pages");
  const [domain, setDomain] = createSignal("");
  const [basePath, setBasePath] = createSignal("");
  const [email, setEmail] = createSignal("");
  const [token, setToken] = createSignal("");
  const [savingCfg, setSavingCfg] = createSignal(false);
  const [publishing, setPublishing] = createSignal(false);
  const [lastDeploy, setLastDeploy] = createSignal("");
  const [publicUrl, setPublicUrl] = createSignal("");

  createEffect(() => {
    const c = cfg();
    if (!c) return;
    setRepo(c.GhRepo ?? "");
    setBranch(c.GhBranch || "gh-pages");
    setDomain(c.GhDomain ?? "");
    setBasePath(c.GhBasePath ?? "");
    setEmail(c.GhEmail ?? "");
    setLastDeploy(c.LastDeploy && !c.LastDeploy.startsWith("0001") ? c.LastDeploy : "");
    setPublicUrl(c.PublicURL ?? "");
  });

  const hasToken = () => cfg()?.HasToken || token().trim() !== "";

  const saveCfg = async () => {
    if (repo().trim() && repo().split("/").length !== 2) return pushToast("仓库格式应为 owner/name", "error");
    setSavingCfg(true);
    try {
      await blogApi.updateDeploySettings({
        GhRepo: repo().trim(),
        GhBranch: branch().trim() || "gh-pages",
        GhDomain: domain().trim(),
        GhBasePath: basePath().trim(),
        GhEmail: email().trim(),
        GhToken: token().trim() || undefined,
      });
      setToken("");
      await refetch();
      pushToast("部署设置已保存", "success");
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "保存失败", "error");
    } finally {
      setSavingCfg(false);
    }
  };

  const publish = async () => {
    if (!repo().trim()) return pushToast("请先填写 GitHub 仓库", "error");
    if (!hasToken()) return pushToast("请先填写 GitHub Token", "error");
    setPublishing(true);
    try {
      // 先保存最新设置，再发布
      await saveCfg();
      const re = await blogApi.publish();
      const item = re.Item;
      pushToast(item?.Summary ?? "已部署", "success");
      if (item?.LastDeploy) setLastDeploy(item.LastDeploy);
      if (item?.PublicURL) setPublicUrl(item.PublicURL);
    } catch (err) {
      pushToast(err instanceof Error ? err.message : "部署失败", "error");
    } finally {
      setPublishing(false);
    }
  };

  return (
    <div class="card p-5">
      <div class="mb-1 flex items-center gap-2 font-medium text-fg">
        <Rocket size={16} />
        GitHub Pages 部署
      </div>
      <p class="mb-4 text-sm text-muted">填写目标仓库与 Personal Access Token（需 repo 权限），即可一键生成并推送。</p>

      <div class="space-y-4">
        <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label="仓库 (owner/name)">
            <input class="input" value={repo()} onInput={(e) => setRepo(e.currentTarget.value)} placeholder="eg: ctaoist/ctaoist.github.io" />
          </Field>
          <Field label="分支">
            <input class="input" value={branch()} onInput={(e) => setBranch(e.currentTarget.value)} placeholder="gh-pages" />
          </Field>
          <Field label="自定义域名 (CNAME，可选)">
            <input class="input" value={domain()} onInput={(e) => setDomain(e.currentTarget.value)} placeholder="eg: blog.example.com" />
          </Field>
          <Field label="Base Path (项目页填 /仓库名，可选)">
            <input class="input" value={basePath()} onInput={(e) => setBasePath(e.currentTarget.value)} placeholder='eg: "" 或 /blog' />
          </Field>
          <Field label="提交邮箱 (可选)">
            <input class="input" value={email()} onInput={(e) => setEmail(e.currentTarget.value)} placeholder="committer email" />
          </Field>
          <Field label="GitHub Token (PAT)">
            <input
              class="input"
              type="password"
              value={token()}
              onInput={(e) => setToken(e.currentTarget.value)}
              placeholder={cfg()?.HasToken ? "已配置（留空保持不变）" : "ghp_..."}
            />
          </Field>
        </div>

        <Show when={publicUrl()}>
          <div class="flex items-center gap-2 text-sm">
            <Globe size={15} class="shrink-0 text-muted" />
            <a class="truncate text-brand-600 hover:underline" href={publicUrl()} target="_blank" rel="noreferrer">
              {publicUrl()}
            </a>
            <Show when={lastDeploy()}>
              <span class="ml-auto whitespace-nowrap text-xs text-muted">上次部署：{fmtTime(lastDeploy())}</span>
            </Show>
          </div>
        </Show>

        <div class="flex flex-wrap items-center justify-end gap-2">
          <Button variant="outline" onClick={() => window.open(blogApi.downloadZipUrl(), "_blank")}>
            <Download size={15} />
            下载 zip
          </Button>
          <Button variant="outline" disabled={savingCfg()} onClick={() => void saveCfg()}>
            <Show when={savingCfg()} fallback={<Save size={15} />}>
              <Loader2 size={15} class="animate-spin" />
            </Show>
            保存部署设置
          </Button>
          <Button variant="primary" disabled={publishing()} onClick={() => void publish()}>
            <Show when={publishing()} fallback={<Rocket size={15} />}>
              <Loader2 size={15} class="animate-spin" />
            </Show>
            生成并部署
          </Button>
        </div>
      </div>
    </div>
  );
}

function fmtTime(s: string): string {
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  return d.toLocaleString();
}

function Field(props: { label: string; children: import("solid-js").JSX.Element }) {
  return (
    <div>
      <label class="mb-1.5 block text-xs text-muted">{props.label}</label>
      {props.children}
    </div>
  );
}

function IconBtn(props: { title: string; danger?: boolean; disabled?: boolean; onClick: () => void; children: import("solid-js").JSX.Element }) {
  return (
    <button
      type="button"
      title={props.title}
      disabled={props.disabled}
      onClick={props.onClick}
      class={`rounded p-1.5 text-muted disabled:opacity-50 ${
        props.danger ? "hover:bg-red-500/10 hover:text-red-500" : "hover:bg-black/5 hover:text-fg dark:hover:bg-white/5"
      }`}
    >
      {props.children}
    </button>
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
