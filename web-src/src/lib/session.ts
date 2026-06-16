import type { User } from "../api/types";

// 解析 Revel 会话 cookie（LEANOTE_SESSION）。后端 cookie.httponly=false，故前端可读。
// 格式（revel v1.0 session_adapter_cookie.go）：
//   Value = Sign(data) + "-" + data
//   data  = urlQueryEscape( 多个 "\x00key:value\x00" 拼接 )
// 解析正则与后端一致：/\x00([^:]*):([^\x00]*)\x00/g
// 注意：这是「尽力而为」的展示用解析；真正的鉴权依据是接口返回（见 client.ts 的 isAuth）。

const COOKIE_NAME = "LEANOTE_SESSION";

function rawCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp("(?:^|;\\s*)" + name + "=([^;]*)"));
  return match ? match[1] : null;
}

function parseRevelSession(value: string): Record<string, string> {
  const hyphen = value.indexOf("-");
  if (hyphen < 0) return {};
  let data = value.slice(hyphen + 1);
  // QueryUnescape：'+' -> 空格，其余 %XX 交给 decodeURIComponent
  data = data.replace(/\+/g, " ");
  let decoded: string;
  try {
    decoded = decodeURIComponent(data);
  } catch {
    decoded = data;
  }
  const out: Record<string, string> = {};
  const re = /\x00([^:]*):([^\x00]*)\x00/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(decoded))) out[m[1]] = m[2];
  return out;
}

/** cookie 是否存在（仅用于路由守卫的快速判断，非权威） */
export function hasSessionCookie(): boolean {
  return !!rawCookie(COOKIE_NAME);
}

/** 从会话 cookie 读取当前用户的展示信息（可能为 null 或字段缺失） */
export function readSessionUser(): Partial<User> | null {
  const raw = rawCookie(COOKIE_NAME);
  if (!raw) return null;
  const m = parseRevelSession(raw);
  if (!m.UserId) return null;
  return {
    UserId: m.UserId,
    Email: m.Email,
    Username: m.Username || m.UsernameRaw || m.Email,
    UsernameRaw: m.UsernameRaw,
    Theme: m.Theme,
    Logo: m.Logo,
    Verified: m.Verified === "1",
    LeftIsMin: m.LeftIsMin === "1",
    NotebookWidth: m.NotebookWidth ? Number(m.NotebookWidth) : undefined,
    NoteListWidth: m.NoteListWidth ? Number(m.NoteListWidth) : undefined,
  };
}
