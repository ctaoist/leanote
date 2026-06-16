// Image-bed config helper: fetches /file/imageBedConfig once per page load and
// caches it (the editor's paste path reads it on every paste). Also adapts the
// wire shape (s3*-prefixed) to the S3BedConfig the browser signer expects.

import { fileApi } from "../api/endpoints";
import type { ImageBedConfig } from "../api/types";
import { buildKey, s3PutObject, type S3BedConfig } from "./s3";

let cache: Promise<ImageBedConfig> | null = null;

export function getImageBed(): Promise<ImageBedConfig> {
  if (!cache) {
    cache = fileApi.imageBedConfig().catch(() => ({ imageBedType: "local" as const }));
  }
  return cache;
}

/** Drop the cache so the next getImageBed() re-fetches (call after admin saves). */
export function clearImageBedCache(): void {
  cache = null;
}

export function toS3BedConfig(c: ImageBedConfig): S3BedConfig {
  return {
    endpoint: c.s3Endpoint ?? "",
    region: c.s3Region || "us-east-1",
    bucket: c.s3Bucket ?? "",
    accessKey: c.s3AccessKey ?? "",
    secretKey: c.s3SecretKey ?? "",
    useSSL: c.s3UseSSL ?? true,
    pathStyle: c.s3PathStyle ?? false,
    publicBaseURL: c.s3PublicBaseURL ?? "",
    keyPrefix: c.s3KeyPrefix ?? "",
  };
}

/** Upload one image to the active S3 bed, honoring its sign mode, and return the
 *  public URL to embed. `name` is the object path under the bed's key prefix —
 *  the original filename, or "album/filename" when an album (prefix) is chosen. */
export async function uploadToBed(bed: ImageBedConfig, name: string, file: File): Promise<string> {
  if (bed.s3SignMode === "server") {
    // 后端签名：换取一次性预签名 URL（后端按 name 生成 key），浏览器 PUT 字节
    const { uploadUrl, publicUrl } = await fileApi.presignImage(name);
    const res = await fetch(uploadUrl, {
      method: "PUT",
      body: file,
      headers: { "Content-Type": file.type || "application/octet-stream" },
    });
    if (!res.ok) throw new Error(`图床上传失败 (${res.status})`);
    return publicUrl;
  }
  // 前端直传：用下发的完整配置在浏览器内 SigV4 直传
  const cfg = toS3BedConfig(bed);
  return s3PutObject(cfg, buildKey(cfg, name), file, file.type || "image/png");
}
