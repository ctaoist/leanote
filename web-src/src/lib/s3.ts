// Browser-side AWS SigV4 for S3-compatible object storage. Used by the image
// bed when imageBedType=s3 and s3SignMode=client: the backend hands the browser
// the full bucket config (incl. secret) and the browser signs + PUTs the image
// directly to S3. Uses the Web Crypto API (crypto.subtle), which requires a
// secure context (https or localhost).
//
// Server sign mode does NOT use this file — there the backend presigns a PUT URL
// and the editor just fetch()es it (see MarkdownEditor).

export interface S3BedConfig {
  endpoint: string; // host[:port], no scheme
  region: string;
  bucket: string;
  accessKey: string;
  secretKey: string;
  useSSL: boolean;
  pathStyle: boolean;
  publicBaseURL: string;
  keyPrefix: string;
}

const enc = new TextEncoder();

// crypto.subtle (Web Crypto) only exists in a secure context — https or
// localhost. Over plain http on a LAN IP it is undefined, so browser-side
// signing is impossible. Fail early with an actionable message instead of a
// cryptic "Cannot read properties of undefined (reading 'digest')".
function ensureSubtle(): void {
  if (!globalThis.crypto?.subtle) {
    throw new Error(
      "当前页面不是安全上下文（需 https 或 localhost），浏览器禁用了 Web Crypto，无法在前端签名。" +
        "请改用 https 访问，或在管理后台把该图床的签名方式改为「后端签名」。"
    );
  }
}

function hex(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

async function sha256Hex(data: BufferSource): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", data));
}

async function hmac(key: BufferSource, msg: string): Promise<ArrayBuffer> {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", k, enc.encode(msg));
}

async function signingKey(secret: string, dateStamp: string, region: string, service: string): Promise<ArrayBuffer> {
  let k: BufferSource = enc.encode("AWS4" + secret);
  k = await hmac(k, dateStamp);
  k = await hmac(k, region);
  k = await hmac(k, service);
  return hmac(k, "aws4_request");
}

// AWS-style percent-encoding over UTF-8 bytes. '/' is kept when encodeSlash=false
// (object key paths).
function awsUriEncode(str: string, encodeSlash: boolean): string {
  const bytes = enc.encode(str);
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (
      (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || (b >= 0x30 && b <= 0x39) ||
      b === 0x2d || b === 0x5f || b === 0x2e || b === 0x7e
    ) {
      out += String.fromCharCode(b);
    } else if (b === 0x2f && !encodeSlash) {
      out += "/";
    } else {
      out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
    }
  }
  return out;
}

function endpointHost(cfg: S3BedConfig): string {
  return cfg.endpoint.replace(/^https?:\/\//, "").replace(/\/+$/, "");
}
function scheme(cfg: S3BedConfig): string {
  return cfg.useSSL ? "https" : "http";
}
function hostHeader(cfg: S3BedConfig): string {
  return cfg.pathStyle ? endpointHost(cfg) : `${cfg.bucket}.${endpointHost(cfg)}`;
}
function canonicalUri(cfg: S3BedConfig, key: string): string {
  let p = "/";
  if (cfg.pathStyle) p += awsUriEncode(cfg.bucket, true) + "/";
  return p + awsUriEncode(key, false);
}
function objectUrl(cfg: S3BedConfig, key: string): string {
  return `${scheme(cfg)}://${hostHeader(cfg)}${canonicalUri(cfg, key)}`;
}

/** The URL embedded in the note for an object (public base if set, else the bucket URL). */
export function publicUrl(cfg: S3BedConfig, key: string): string {
  if (cfg.publicBaseURL) return cfg.publicBaseURL.replace(/\/+$/, "") + "/" + awsUriEncode(key, false);
  return objectUrl(cfg, key);
}

/** The object key for an upload: the bed's key prefix + the desired path
 *  (`filename` or `album/filename`). The filename is preserved as-is, so the
 *  same name overwrites by design. The caller is responsible for the path. */
export function buildKey(cfg: S3BedConfig, name: string): string {
  const prefix = cfg.keyPrefix.replace(/^\/+/, "");
  return prefix + name.replace(/^\/+/, "");
}

function amzDates(d: Date): { amzDate: string; dateStamp: string } {
  const amzDate = d.toISOString().replace(/[:-]/g, "").replace(/\.\d{3}/, "");
  return { amzDate, dateStamp: amzDate.slice(0, 8) };
}

// Header-signed SigV4. Signs host + x-amz-content-sha256 + x-amz-date; Content-Type
// is sent unsigned (S3 ignores unsigned headers for the signature).
async function signRequest(
  cfg: S3BedConfig,
  method: string,
  key: string,
  payloadHash: string
): Promise<{ url: string; headers: Record<string, string> }> {
  if (!crypto?.subtle) {
    throw new Error("浏览器直传需安全上下文（https 或 localhost）；或在管理后台改用『后端签名』模式");
  }
  const host = hostHeader(cfg);
  const url = objectUrl(cfg, key);
  const region = cfg.region || "us-east-1";
  const { amzDate, dateStamp } = amzDates(new Date());
  const scope = `${dateStamp}/${region}/s3/aws4_request`;
  const cUri = canonicalUri(cfg, key);
  const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = "host;x-amz-content-sha256;x-amz-date";
  const canonicalRequest = [method, cUri, "", canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, await sha256Hex(enc.encode(canonicalRequest))].join("\n");
  const sig = hex(await hmac(await signingKey(cfg.secretKey, dateStamp, region, "s3"), stringToSign));
  const authorization = `AWS4-HMAC-SHA256 Credential=${cfg.accessKey}/${scope}, SignedHeaders=${signedHeaders}, Signature=${sig}`;
  return {
    url,
    headers: { "x-amz-content-sha256": payloadHash, "x-amz-date": amzDate, Authorization: authorization },
  };
}

/** Directly PUT an image to S3 and return the public URL to embed. */
export async function s3PutObject(cfg: S3BedConfig, key: string, body: Blob, contentType: string): Promise<string> {
  ensureSubtle();
  const payloadHash = await sha256Hex(await body.arrayBuffer());
  const { url, headers } = await signRequest(cfg, "PUT", key, payloadHash);
  const res = await fetch(url, { method: "PUT", body, headers: { ...headers, "Content-Type": contentType } });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`图床上传失败 (${res.status})${text ? ": " + text.slice(0, 120) : ""}`);
  }
  return publicUrl(cfg, key);
}

/** Delete an object (used by the admin "test connection" cleanup). 404 is OK. */
export async function s3DeleteObject(cfg: S3BedConfig, key: string): Promise<void> {
  ensureSubtle();
  const payloadHash = await sha256Hex(enc.encode(""));
  const { url, headers } = await signRequest(cfg, "DELETE", key, payloadHash);
  const res = await fetch(url, { method: "DELETE", headers });
  if (!res.ok && res.status !== 404) {
    throw new Error(`删除失败 (${res.status})`);
  }
}
