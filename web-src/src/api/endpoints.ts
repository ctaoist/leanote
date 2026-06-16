import { api } from "./client";
import { newObjectId } from "../lib/objectId";
import type { Note, NoteAndContent, Notebook, Re, Attachment, FileImage, PageList, User, NoteHistory, Album, AdminStats, AdminUserRow, AdminConfigs, ImageBed, ImageBedConfig, BedListing, UserImageBedSettings, UserBlogSettings, BlogTheme, BlogDeploySettings } from "./types";

// ============ 引导 / 当前用户 ============
// 新 Go 后端提供干净的 JSON 端点 `GET /user/info`：已登录返回 User，未登录返回
// 401。不再抓取 /note 页面里注入的 `var UserInfo = {...}`。
export const bootstrapApi = {
  async fetchUserInfo(): Promise<Partial<User> | null> {
    try {
      return await api.get<User>("/user/info");
    } catch {
      // 401 / 网络错误 → 视为未登录
      return null;
    }
  },
};

// ============ 认证 ============
export const authApi = {
  login: (email: string, pwd: string, captcha = "") =>
    api.post<Re>("/doLogin", { email, pwd, captcha }),
  logout: () => api.get<unknown>("/logout"),
  register: (email: string, pwd: string, iu = "") =>
    api.post<Re>("/doRegister", { email, pwd, iu }),
  findPassword: (email: string, captcha = "") =>
    api.post<Re>("/doFindPassword", { email, captcha }),
  findPasswordUpdate: (token: string, pwd: string) =>
    api.post<Re>("/findPasswordUpdate", { token, pwd }),
  captchaUrl: () => `/captcha/get?${Date.now()}`,
};

// ============ 笔记本 ============
export const notebookApi = {
  list: () => api.get<Notebook[]>("/notebook/getNotebooks"),
  add: (title: string, parentNotebookId = "") =>
    api.post<Notebook | false>("/notebook/addNotebook", {
      notebookId: newObjectId(),
      title,
      parentNotebookId,
    }),
  updateTitle: (notebookId: string, title: string) =>
    api.post<boolean>("/notebook/updateNotebookTitle", { notebookId, title }),
  delete: (notebookId: string) =>
    api.get<Re>("/notebook/deleteNotebook", { notebookId }),
  drag: (data: { curNotebookId: string; parentNotebookId?: string; siblings: string[] }) =>
    api.post<boolean>("/notebook/dragNotebooks", { data: JSON.stringify(data) }),
};

// ============ 笔记 ============
export type NewNoteInput = {
  NotebookId: string;
  Title?: string;
  Content?: string;
  Abstract?: string;
  Tags?: string[];
  IsMarkdown?: boolean;
  IsBlog?: boolean;
};

export type UpdateNoteInput = {
  NoteId: string;
  Title?: string;
  Content?: string;
  Abstract?: string;
  Tags?: string[];
  Desc?: string;
  ImgSrc?: string;
};

export const noteApi = {
  list: (notebookId = "") => api.get<Note[]>("/note/listNotes", { notebookId }),
  trash: () => api.get<Note[]>("/note/listTrashNotes"),
  getAndContent: (noteId: string) =>
    api.get<NoteAndContent>("/note/getNoteAndContent", { noteId }),
  getContent: (noteId: string) =>
    api.get<NoteAndContent>("/note/getNoteContent", { noteId }),
  create: (note: NewNoteInput) =>
    api.post<Note>("/note/updateNoteOrContent", {
      IsNew: true,
      NoteId: newObjectId(),
      NotebookId: note.NotebookId,
      Title: note.Title ?? "",
      Content: note.Content ?? "",
      Abstract: note.Abstract ?? "",
      Tags: (note.Tags ?? []).join(","),
      IsMarkdown: !!note.IsMarkdown,
      IsBlog: !!note.IsBlog,
    }),
  // 仅发送需要更新的字段（后端用 c.Has(field) 判定）
  update: (note: UpdateNoteInput) => {
    const payload: Record<string, string> = { NoteId: note.NoteId };
    if (note.Title !== undefined) payload.Title = note.Title;
    if (note.Content !== undefined) payload.Content = note.Content;
    if (note.Abstract !== undefined) payload.Abstract = note.Abstract;
    if (note.Tags !== undefined) payload.Tags = note.Tags.join(",");
    if (note.Desc !== undefined) payload.Desc = note.Desc;
    if (note.ImgSrc !== undefined) payload.ImgSrc = note.ImgSrc;
    return api.post<boolean>("/note/updateNoteOrContent", payload);
  },
  delete: (noteIds: string[], isShared = false) =>
    api.post<boolean>("/note/deleteNote", { noteIds, isShared }),
  restore: (noteIds: string[]) =>
    api.post<boolean>("/note/restoreNote", { noteIds }),
  deleteTrash: (noteIds: string[]) =>
    api.post<boolean>("/note/deleteTrash", { noteIds }),
  move: (noteIds: string[], notebookId: string) =>
    api.post<boolean>("/note/moveNote", { noteIds, notebookId }),
  copy: (noteIds: string[], notebookId: string) =>
    api.post<Re<Note[]>>("/note/copyNote", { noteIds, notebookId }),
  // 注意：searchNote 必须用 POST —— GET /note/searchNote 会被页面路由
  // `GET /note/:noteId` 抢占（返回 HTML）。POST 才会命中 Note.SearchNote。
  search: (key: string) => api.post<Note[]>("/note/searchNote", { key }),
  searchByTags: (tags: string[]) => api.get<Note[]>("/note/searchNoteByTags", { tags }),
  setBlog: (noteIds: string[], isBlog: boolean, isTop = false) =>
    api.post<boolean>("/note/setNote2Blog", { noteIds, isBlog, isTop }),
  updateBlogMeta: (noteId: string, meta: { UrlTitle?: string; Desc?: string; ImgSrc?: string }) => {
    const data: Record<string, string> = { noteId };
    if (meta.UrlTitle !== undefined) data.UrlTitle = meta.UrlTitle;
    if (meta.Desc !== undefined) data.Desc = meta.Desc;
    if (meta.ImgSrc !== undefined) data.ImgSrc = meta.ImgSrc;
    return api.post<Re<{ UrlTitle: string }>>("/note/updateBlogMeta", data);
  },
};

// ============ 笔记历史 ============
export const noteHistoryApi = {
  // GET /noteContentHistory/listHistories?noteId= → NoteHistory[]（无历史时返回非数组）
  list: (noteId: string) =>
    api.get<NoteHistory[]>("/noteContentHistory/listHistories", { noteId }),
};

// ============ 标签 ============
export const tagApi = {
  update: (tag: string) => api.post<unknown>("/tag/updateTag", { tag }),
  delete: (tag: string) => api.post<unknown>("/tag/deleteTag", { tag }),
};

// ============ 用户设置 ============
export const userApi = {
  updateUsername: (username: string) =>
    api.post<Re>("/user/updateUsername", { username }),
  updatePwd: (oldPwd: string, pwd: string) =>
    api.post<Re>("/user/updatePwd", { oldPwd, pwd }),
  updateTheme: (theme: string) => api.post<Re>("/user/updateTheme", { theme }),
  updateColumnWidth: (notebookWidth: number, noteListWidth: number) =>
    api.post<unknown>("/user/updateColumnWidth", { notebookWidth, noteListWidth }),
  updateLeftIsMin: (leftIsMin: boolean) =>
    api.post<unknown>("/user/updateLeftIsMin", { leftIsMin }),
  // 未验证邮箱时重发激活邮件
  resendActiveEmail: () => api.post<Re>("/user/reSendActiveEmail", {}),

  // ----- 用户级图床设置 -----
  // 当前用户的图床设置（含 secret，是用户自己的凭证，供设置表单回填）
  getImageBedSettings: async (): Promise<UserImageBedSettings> => {
    const re = await api.get<Re<UserImageBedSettings>>("/user/imageBedSettings");
    return (re.Item as UserImageBedSettings) ?? {
      imageBedType: "local",
      imageBedActiveId: "",
      imageBeds: [],
      imagePageSize: 12,
      allowLocalImageBed: true,
    };
  },
  updateImageBedSettings: (patch: Partial<UserImageBedSettings>) => {
    const data: Record<string, string> = {};
    if (patch.imageBedType !== undefined) data.imageBedType = patch.imageBedType;
    if (patch.imageBedActiveId !== undefined) data.imageBedActiveId = patch.imageBedActiveId;
    if (patch.imageBeds !== undefined) data.imageBeds = JSON.stringify(patch.imageBeds);
    if (patch.imagePageSize !== undefined) data.imagePageSize = String(patch.imagePageSize);
    return api.post<Re>("/user/updateImageBedSettings", data);
  },
  // 后端签名模式的「测试连接」：用后端预签名 PUT/DELETE（浏览器普通 fetch，无需 Web Crypto）
  presignBedTest: async (bed: ImageBed): Promise<{ putUrl: string; deleteUrl: string; key: string }> => {
    const re = await api.post<Re<{ putUrl: string; deleteUrl: string; key: string }>>(
      "/user/presignBedTest",
      { bed: JSON.stringify(bed) }
    );
    return re.Item as { putUrl: string; deleteUrl: string; key: string };
  },
};

// ============ 图片 / 附件 ============
export const fileApi = {
  pasteImage: (noteId: string, file: File) => {
    const data = new FormData();
    data.set("noteId", noteId);
    data.set("from", "pasteImage");
    data.set("file", file);
    return api.post<Re>("/file/pasteImage", data);
  },
  uploadImage: (noteId: string, file: File) => {
    const data = new FormData();
    data.set("noteId", noteId);
    data.set("file", file);
    return api.post<Re>("/file/uploadImageLeaui", data);
  },
  // 上传图片到指定相册（albumId 为空则进默认相册）
  uploadToAlbum: (albumId: string, file: File) => {
    const data = new FormData();
    data.set("albumId", albumId);
    data.set("file", file);
    return api.post<Re<FileImage>>("/file/uploadImageLeaui", data);
  },
  // 头像上传：返回 Re，Id 为头像静态路径（public/upload/.../logo/...）
  uploadAvatar: (file: File) => {
    const data = new FormData();
    data.set("file", file);
    return api.post<Re>("/file/uploadAvatar", data);
  },
  listImages: (albumId = "", page = 1, key = "", pageSize?: number) =>
    api.get<PageList<FileImage>>("/file/getImages", { albumId, page, key, pageSize }),
  updateImageTitle: (fileId: string, title: string) =>
    api.post<boolean>("/file/updateImageTitle", { fileId, title }),
  deleteImage: (fileId: string) =>
    api.post<Re>("/file/deleteImage", { fileId }),
  imageUrl: (fileId: string) =>
    `/file/outputImage?fileId=${encodeURIComponent(fileId)}`,
  // 图床：上传端配置（local 时仅 {imageBedType}；s3+client 含完整凭证）
  imageBedConfig: async (): Promise<ImageBedConfig> => {
    const re = await api.get<Re<ImageBedConfig>>("/file/imageBedConfig");
    return (re.Item as ImageBedConfig) ?? { imageBedType: "local" };
  },
  // 图床 server 模式：换取一次性预签名 PUT URL。name=目标对象路径（原文件名，或 相册/文件名）
  presignImage: async (name: string): Promise<{ uploadUrl: string; publicUrl: string; key: string }> => {
    const re = await api.post<Re<{ uploadUrl: string; publicUrl: string; key: string }>>("/file/presignImage", { name });
    return re.Item as { uploadUrl: string; publicUrl: string; key: string };
  },
  // 图床浏览：列举 active bed 下 prefix 的子前缀（相册）与对象。prefix 空=顶层（bed 的 keyPrefix）。
  // size = 每页张数（max-keys）；相册侧栏传大值以取全部前缀。
  bedImages: async (prefix = "", token = "", size?: number): Promise<BedListing> => {
    const re = await api.get<Re<BedListing>>("/file/bedImages", { prefix, token, size });
    return (re.Item as BedListing) ?? { prefixes: [], images: [] };
  },
  // 图床对象/相册（前缀）管理——后端用 active bed 凭证执行（client/server 模式皆可）
  bedDeleteObject: (key: string) => api.post<Re>("/file/bedDeleteObject", { key }),
  bedCreatePrefix: (name: string) => api.post<Re>("/file/bedCreatePrefix", { name }),
  bedDeletePrefix: (prefix: string) => api.post<Re>("/file/bedDeletePrefix", { prefix }),
  bedRenamePrefix: (oldPrefix: string, newName: string) =>
    api.post<Re>("/file/bedRenamePrefix", { oldPrefix, newName }),
};

// ============ 相册 ============
export const albumApi = {
  list: () => api.get<Album[]>("/album/getAlbums"),
  add: (name: string) => api.post<Album | false>("/album/addAlbum", { name }),
  update: (albumId: string, name: string) =>
    api.post<boolean>("/album/updateAlbum", { albumId, name }),
  delete: (albumId: string) => api.post<Re>("/album/deleteAlbum", { albumId }),
};

export const attachApi = {
  list: (noteId: string) => api.get<Attachment[]>("/attach/getAttachs", { noteId }),
  upload: (noteId: string, file: File) => {
    const data = new FormData();
    data.set("noteId", noteId);
    data.set("file", file);
    return api.post<Re>("/attach/uploadAttach", data);
  },
  delete: (attachId: string) => api.post<Re>("/attach/deleteAttach", { attachId }),
  downloadUrl: (attachId: string) =>
    `/attach/download?attachId=${encodeURIComponent(attachId)}`,
};

// ============ 管理后台（仅管理员） ============
export const adminApi = {
  stats: async (): Promise<AdminStats> => {
    const re = await api.get<Re<AdminStats>>("/admin/stats");
    return re.Item as AdminStats;
  },
  listUsers: (params: { page?: number; pageSize?: number; sorter?: string; keywords?: string } = {}) =>
    api.get<PageList<AdminUserRow>>("/admin/listUsers", {
      page: params.page ?? 1,
      pageSize: params.pageSize,
      sorter: params.sorter,
      keywords: params.keywords,
    }),
  addUser: (email: string, pwd: string) => api.post<Re>("/admin/addUser", { email, pwd }),
  resetPwd: (userId: string, pwd: string) => api.post<Re>("/admin/resetPwd", { userId, pwd }),
  getConfigs: async (): Promise<AdminConfigs> => {
    const re = await api.get<Re<AdminConfigs>>("/admin/getConfigs");
    return re.Item as AdminConfigs;
  },
  updateConfigs: (patch: Partial<AdminConfigs>) => {
    const data: Record<string, string> = {};
    if (patch.openRegister !== undefined) data.openRegister = String(patch.openRegister);
    if (patch.uploadImageSize !== undefined) data.uploadImageSize = String(patch.uploadImageSize);
    if (patch.uploadAttachSize !== undefined) data.uploadAttachSize = String(patch.uploadAttachSize);
    if (patch.uploadAvatarSize !== undefined) data.uploadAvatarSize = String(patch.uploadAvatarSize);
    if (patch.allowLocalImageBed !== undefined) data.allowLocalImageBed = String(patch.allowLocalImageBed);
    return api.post<Re>("/admin/updateConfigs", data);
  },
};

// ============ 博客设置（用户级；含主题：选择/编辑/导入/导出） ============
export const blogApi = {
  getSettings: async (): Promise<UserBlogSettings> => {
    const re = await api.get<Re<UserBlogSettings>>("/user/blogSettings");
    return re.Item as UserBlogSettings;
  },
  updateSettings: (patch: Partial<UserBlogSettings>) => {
    const data: Record<string, string> = {};
    if (patch.Title !== undefined) data.Title = patch.Title;
    if (patch.SubTitle !== undefined) data.SubTitle = patch.SubTitle;
    if (patch.AboutMe !== undefined) data.AboutMe = patch.AboutMe;
    if (patch.CanComment !== undefined) data.CanComment = String(patch.CanComment);
    if (patch.CommentType !== undefined) data.CommentType = patch.CommentType;
    if (patch.DisqusId !== undefined) data.DisqusId = patch.DisqusId;
    if (patch.PerPageSize !== undefined) data.PerPageSize = String(patch.PerPageSize);
    if (patch.SortField !== undefined) data.SortField = patch.SortField;
    if (patch.IsAsc !== undefined) data.IsAsc = String(patch.IsAsc);
    if (patch.BlogType !== undefined) data.BlogType = patch.BlogType;
    if (patch.SubDomain !== undefined) data.SubDomain = patch.SubDomain;
    if (patch.Domain !== undefined) data.Domain = patch.Domain;
    return api.post<Re>("/user/updateBlogSettings", data);
  },
  // 主题：列表 / 设为当前 / 删除
  listThemes: async (): Promise<BlogTheme[]> => {
    const re = await api.get<Re<BlogTheme[]>>("/user/themes");
    return (re.Item as BlogTheme[]) ?? [];
  },
  activeTheme: (themeId: string) => api.post<Re>("/user/activeTheme", { themeId }),
  deleteTheme: (themeId: string) => api.post<Re>("/user/deleteTheme", { themeId }),
  // 主题文件编辑
  listThemeFiles: async (themeId: string): Promise<string[]> => {
    const re = await api.get<Re<string[]>>("/user/themeFiles", { themeId });
    return (re.Item as string[]) ?? [];
  },
  getThemeFile: async (themeId: string, filename: string): Promise<string> => {
    const re = await api.get<Re<string>>("/user/themeFile", { themeId, filename });
    return (re.Item as string) ?? "";
  },
  updateThemeFile: (themeId: string, filename: string, content: string) =>
    api.post<Re>("/user/updateThemeFile", { themeId, filename, content }),
  deleteThemeFile: (themeId: string, filename: string) =>
    api.post<Re>("/user/deleteThemeFile", { themeId, filename }),
  uploadThemeImage: (themeId: string, file: File) => {
    const data = new FormData();
    data.set("themeId", themeId);
    data.set("file", file);
    return api.post<Re>("/user/uploadThemeImage", data);
  },
  // 导入 .zip / 导出（下载）
  importTheme: (file: File) => {
    const data = new FormData();
    data.set("file", file);
    return api.post<Re<{ themeId: string; name: string }>>("/user/importTheme", data);
  },
  exportThemeUrl: (themeId: string) => `/user/exportTheme?themeId=${encodeURIComponent(themeId)}`,

  // ---- 静态博客部署（GitHub Pages） ----
  getDeploySettings: async (): Promise<BlogDeploySettings> => {
    const re = await api.get<Re<BlogDeploySettings>>("/user/blogDeploySettings");
    return re.Item as BlogDeploySettings;
  },
  updateDeploySettings: (patch: Partial<BlogDeploySettings> & { GhToken?: string }) => {
    const data: Record<string, string> = {};
    if (patch.GhRepo !== undefined) data.GhRepo = patch.GhRepo;
    if (patch.GhBranch !== undefined) data.GhBranch = patch.GhBranch;
    if (patch.GhDomain !== undefined) data.GhDomain = patch.GhDomain;
    if (patch.GhBasePath !== undefined) data.GhBasePath = patch.GhBasePath;
    if (patch.GhEmail !== undefined) data.GhEmail = patch.GhEmail;
    if (patch.GhToken) data.GhToken = patch.GhToken; // 仅在填写时提交
    return api.post<Re>("/user/updateBlogDeploySettings", data);
  },
  publish: () =>
    api.post<Re<{ Summary: string; Pages: number; PublicURL: string; LastDeploy: string }>>("/user/publishBlog"),
  downloadZipUrl: () => "/user/downloadBlogZip",
  previewUrl: () => "/blog/preview",
};
