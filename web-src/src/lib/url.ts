// 头像 / Logo 路径归一：后端返回的 Logo 可能是相对路径（如 public/upload/.../logo/x.png）、
// 绝对路径或完整 URL。统一成可直接用于 <img src> 的地址；空值返回 undefined（交由占位）。
export function avatarUrl(logo?: string): string | undefined {
  if (!logo) return undefined;
  if (logo.startsWith("http") || logo.startsWith("/")) return logo;
  return "/" + logo;
}
