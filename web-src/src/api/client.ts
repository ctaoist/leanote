import type { Re } from "./types";

export class ApiError extends Error {
  status?: number;
  payload?: unknown;
  /** 登录态失效（后端返回 HTML 登录页而非 JSON） */
  isAuth?: boolean;

  constructor(message: string, opts: { status?: number; payload?: unknown; isAuth?: boolean } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = opts.status;
    this.payload = opts.payload;
    this.isAuth = opts.isAuth;
  }
}

type Primitive = string | number | boolean;
export type Query = Record<string, Primitive | Primitive[] | undefined | null>;

const FORM_METHODS = new Set(["POST", "PUT", "PATCH"]);

function hasOkShape(value: unknown): value is Re {
  return !!value && typeof value === "object" && "Ok" in value;
}

function encodeQuery(query?: Query): string {
  if (!query) return "";
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null) continue;
    // Revel 数组绑定需要 key[]=v 形式
    if (Array.isArray(value)) value.forEach((v) => params.append(`${key}[]`, String(v)));
    else params.append(key, String(value));
  }
  const text = params.toString();
  return text ? `?${text}` : "";
}

function toFormBody(data?: Query | FormData): BodyInit | undefined {
  if (!data) return undefined;
  if (data instanceof FormData) return data;
  const body = new URLSearchParams();
  for (const [key, value] of Object.entries(data)) {
    if (value === undefined || value === null) continue;
    // Revel 数组绑定需要 key[]=v 形式
    if (Array.isArray(value)) value.forEach((v) => body.append(`${key}[]`, String(v)));
    else body.set(key, String(value));
  }
  return body;
}

async function parseResponse<T>(response: Response): Promise<T> {
  const contentType = response.headers.get("content-type") || "";
  const isJson = contentType.includes("application/json");
  const payload = isJson ? await response.json() : await response.text();

  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      throw new ApiError("登录态失效，请重新登录", { status: response.status, payload, isAuth: true });
    }
    throw new ApiError(`HTTP ${response.status}`, { status: response.status, payload });
  }

  // 后端在未登录时常常返回 HTML 登录页（200），需识别
  if (typeof payload === "string") {
    const trimmed = payload.trim();
    if (trimmed.startsWith("<!DOCTYPE") || trimmed.startsWith("<html")) {
      throw new ApiError("登录态失效，请重新登录", { status: response.status, payload, isAuth: true });
    }
  }

  if (hasOkShape(payload) && payload.Ok === false) {
    throw new ApiError(payload.Msg || "请求失败", { status: response.status, payload });
  }

  return payload as T;
}

async function request<T>(path: string, init: RequestInit = {}, query?: Query): Promise<T> {
  const url = `${path}${encodeQuery(query)}`;
  const isForm = init.body instanceof FormData;
  const response = await fetch(url, {
    credentials: "include",
    ...init,
    headers: {
      Accept: "application/json, text/plain;q=0.9, */*;q=0.8",
      ...(isForm ? {} : FORM_METHODS.has(init.method || "")
        ? { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" }
        : {}),
      ...init.headers,
    },
  });
  return parseResponse<T>(response);
}

export const api = {
  get<T>(path: string, query?: Query) {
    return request<T>(path, { method: "GET" }, query);
  },
  post<T>(path: string, data?: Query | FormData) {
    return request<T>(path, { method: "POST", body: toFormBody(data) });
  },
};
