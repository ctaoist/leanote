// Leanote 数据类型 —— 与 Go 后端 JSON 字段保持一致（大驼峰）。
// 参考：leanote/app/info/*.go 与 app/views/note/note.html 注入的全局变量。

export type LeanoteId = string;

/** 变更类接口的统一响应包裹（/doLogin, /notebook/addNotebook 等） */
export interface Re<T = unknown> {
  Ok?: boolean;
  Code?: number;
  Msg?: string;
  Id?: string;
  List?: unknown;
  Item?: T;
  Token?: string;
  UserId?: string;
  Email?: string;
  Username?: string;
}

export interface User {
  UserId: LeanoteId;
  Email: string;
  Username: string;
  UsernameRaw?: string;
  Verified?: boolean;
  Logo?: string;
  Theme?: string;
  NotebookWidth?: number;
  NoteListWidth?: number;
  MdEditorWidth?: number;
  LeftIsMin?: boolean;
  BlogUrl?: string;
  PostUrl?: string;
  /** 后端派生：当前用户是否为管理员（Username == 配置的管理员名） */
  IsAdmin?: boolean;
}

export interface Notebook {
  NotebookId: LeanoteId;
  UserId?: LeanoteId;
  ParentNotebookId?: LeanoteId;
  ChildNotebookIds?: LeanoteId[];
  Seq?: number;
  Title: string;
  UrlTitle?: string;
  NumberNotes?: number;
  IsTrash?: boolean;
  IsBlog?: boolean;
  IsDeleted?: boolean;
  CreatedTime?: string;
  UpdatedTime?: string;
  Subs?: Notebook[];
}

export interface Note {
  NoteId: LeanoteId;
  UserId?: LeanoteId;
  CreatedUserId?: LeanoteId;
  NotebookId: LeanoteId;
  Title: string;
  Desc?: string;
  Src?: string;
  ImgSrc?: string;
  Tags?: string[];
  IsTrash?: boolean;
  IsBlog?: boolean;
  UrlTitle?: string;
  IsTop?: boolean;
  ReadNum?: number;
  LikeNum?: number;
  CommentNum?: number;
  IsMarkdown?: boolean;
  AttachNum?: number;
  CreatedTime?: string;
  UpdatedTime?: string;
  PublicTime?: string;
  Usn?: number;
  IsDeleted?: boolean;
  // 内容（getNoteAndContent 时附带）
  Content?: string;
  Abstract?: string;
  IsNew?: boolean;
  FromUserId?: LeanoteId;
}

export interface NoteContent {
  NoteId: LeanoteId;
  UserId?: LeanoteId;
  IsBlog?: boolean;
  Content: string;
  Abstract?: string;
  CreatedTime?: string;
  UpdatedTime?: string;
  UpdatedUserId?: LeanoteId;
}

export type NoteAndContent = Note & NoteContent;

export interface TagInfo {
  Tag: string;
  Count?: number;
  Usn?: number;
}

/** 笔记内容历史版本（/noteContentHistory/listHistories 返回数组项） */
export interface NoteHistory {
  UpdatedUserId?: LeanoteId;
  UpdatedTime: string;
  /** Markdown 笔记为 md 源码，富文本为 HTML */
  Content: string;
}

export interface Attachment {
  AttachId: LeanoteId;
  FileId?: LeanoteId;
  NoteId?: LeanoteId;
  Title?: string;
  Name?: string;
  Size?: number;
  Type?: string;
  CreatedTime?: string;
}

export interface FileImage {
  FileId: LeanoteId;
  AlbumId?: LeanoteId;
  Title?: string;
  Name?: string;
  Path?: string;
  Size?: number;
  CreatedTime?: string;
}

export interface PageList<T> {
  Count: number;
  List: T[];
}

export interface Album {
  AlbumId: LeanoteId;
  Name: string;
  Type?: number;
  Seq?: number;
  CreatedTime?: string;
}

// ============ 管理后台 ============

export interface AdminStats {
  UserCount: number;
  NoteCount: number;
  BlogCount: number;
}

/** 管理后台用户列表行（后端 adminUserView，含注册时间） */
export interface AdminUserRow {
  UserId: LeanoteId;
  Email: string;
  Username: string;
  Verified: boolean;
  CreatedTime: string;
}

/** 一个已配置的网络图床（对应后端 imagebed.Bed，camelCase）。 */
export interface ImageBed {
  id: string;
  name: string;
  signMode: "client" | "server";
  endpoint: string;
  region: string;
  bucket: string;
  accessKey: string;
  secretKey: string;
  useSSL: boolean;
  pathStyle: boolean;
  publicBaseURL: string;
  keyPrefix: string;
}

export interface AdminConfigs {
  openRegister: boolean;
  uploadImageSize: number;
  uploadAttachSize: number;
  uploadAvatarSize: number;
  /** 是否允许用户把图床设为「本地存储」（关闭后用户只能用 S3） */
  allowLocalImageBed: boolean;
}

/** 用户级图床设置（每个用户配置自己的图床；含「每页图片数」）。 */
export interface UserImageBedSettings {
  imageBedType: "local" | "s3";
  imageBedActiveId: string;
  imageBeds: ImageBed[];
  /** 图片选择器每页张数（本地与 S3 共用） */
  imagePageSize: number;
  /** 只读：管理员是否允许本地图床（false 时本地选项不可用） */
  allowLocalImageBed?: boolean;
}

/** 用户级博客设置（/user/blogSettings，后端 PascalCase 透传，存于 user_blogs）。 */
export interface UserBlogSettings {
  Title: string;
  SubTitle: string;
  AboutMe: string;
  Logo: string;
  CanComment: boolean;
  CommentType: "default" | "disqus";
  DisqusId: string;
  PerPageSize: number;
  SortField: string;
  IsAsc: boolean;
  ThemeId: string;
  ThemeName: string;
  BlogType: "dynamic" | "static";
  /** 子域名博客：<SubDomain>.<管理员配置的基础域名> 在根路径渲染本博客 */
  SubDomain: string;
  /** 独立域名博客：绑定的自定义域名（如 blog.example.com）在根路径渲染本博客 */
  Domain: string;
  /** 只读：管理员配置的子域名基础域名（用于展示成品地址；空=未启用子域名博客） */
  BlogBaseDomain?: string;
}

/** 静态博客的 GitHub Pages 部署配置（Token 只写不回；后端只返回 HasToken）。 */
export interface BlogDeploySettings {
  BlogType: "dynamic" | "static";
  GhRepo: string;
  GhBranch: string;
  GhDomain: string;
  GhBasePath: string;
  GhEmail: string;
  HasToken: boolean;
  LastDeploy: string;
  PublicURL: string;
}

/** 一个博客主题（/user/themes，后端 themes 集合，文件型主题）。 */
export interface BlogTheme {
  ThemeId: string;
  Name: string;
  Version: string;
  Author: string;
  AuthorUrl: string;
  IsActive: boolean;
  IsDefault: boolean;
}

/** 图床浏览（/file/bedImages）：前缀=相册，images 带后端算好的公开 URL。 */
export interface BedImage {
  key: string;
  url: string;
  size?: number;
}
export interface BedListing {
  prefixes: string[];
  images: BedImage[];
  next?: string;
}

/** 上传端拿到的图床配置（/file/imageBedConfig）。server 模式不含 secret/凭证。 */
export interface ImageBedConfig {
  imageBedType: "local" | "s3";
  /** 图片选择器每页张数（本地与 S3 共用，普通用户也能拿到） */
  imagePageSize?: number;
  s3SignMode?: "client" | "server";
  s3PublicBaseURL?: string;
  s3KeyPrefix?: string;
  // 仅 client 模式返回（浏览器需自签）
  s3Endpoint?: string;
  s3Region?: string;
  s3Bucket?: string;
  s3AccessKey?: string;
  s3SecretKey?: string;
  s3UseSSL?: boolean;
  s3PathStyle?: boolean;
}

