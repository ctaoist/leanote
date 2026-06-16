# Leanote

- 使用 Go Fiber v2 重新实现 Leanote 后端，前端使用 SolidJs 和 TailwindCSS 重写。
- 图床支持本地模式（存服务器上）和通用 S3 协议网络图床存储。
- 单二进制打包发布 (embedded SPA)。
- 同时支持动态博客或者静态博客，动态博客可自定义域名或者添加子域名，静态博客支持上传 Github Pages 和下载 zip 包。
- 博客主题导入与编辑

![](screenshots/note.png)

![](screenshots/admin_imageBed.png)

![](screenshots/admin_blog.png)

## 从源码运行

```bash
go build ./...
PORT=9016 go run .
```

前端使用环境变量 `LEANOTE_BACKEND` 来指定后端:

```bash
cd ../web-src
LEANOTE_BACKEND=http://127.0.0.1:9016 npm run dev   # http://localhost:5173
```

## 编译打包

```bash
# 1. build the frontend FIRST — vite writes straight into web-src/dist
cd web-src && npm run build
# 2. then build the backend from the repo root — go:embed bakes web-src/dist in
cd .. && CGO_ENABLED=0 go build -ldflags="-s -w" -o leanote .
PORT=9016 ./leanote          # open http://<host>:9016/
```

## 配置

配置优先级: **内部默认值 < YAML 配置文件 < 环境变量**.

复制 [`config.example.yaml`](config.example.yaml) 为 `config.yaml`, 或者通过参数指定:

```bash
./leanote -config /etc/leanote.yaml
```

| YAML key | Env var | Default | Purpose |
|----------|---------|---------|---------|
| `mongo_uri` | `MONGO_URI` | `mongodb://user:password@127.0.0.1:27017/leanote?authSource=admin` | MongoDB connection |
| `mongo_db` | `MONGO_DB` | `leanote` | Database name — **point at a copy/backup to test writes safely** |
| `port` | `PORT` | `9016` | HTTP listen port |
| `file_root` | `FILE_ROOT` | `/leanote` | On-disk root for images/attachments/avatars (the live install, so legacy files resolve and new files land beside them) |
| `session_secret` | `SESSION_SECRET` | `dev-insecure-...` | Session secret — change in production |
| `session_ttl` | `SESSION_TTL` | `72h` | Session cookie + TTL index lifetime |
| `admin_username` | `ADMIN_USERNAME` | `user` | Admin username (this DB's admin) |
