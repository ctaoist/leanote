package handler

import (
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"leanote/internal/imagebed"
	"leanote/internal/types"
)

// ImageBedConfig tells the browser how to upload images. For local mode it
// returns only the type. For s3 mode it always returns the sign mode; the full
// credentials (incl. secret) are returned ONLY in client sign mode, where the
// browser signs in-browser. In server mode the browser instead calls
// /file/presignImage per upload and the secret never leaves the server.
func (h *Handler) ImageBedConfig(c *fiber.Ctx) error {
	u, err := h.loadUser(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrRe("未登录"))
	}
	if userImageBedType(u) != "s3" {
		return c.JSON(types.OkItem(fiber.Map{
			"imageBedType":  "local",
			"imagePageSize": userImagePageSize(u),
		}))
	}
	mode := userS3SignMode(u)
	s := userS3Config(u)
	m := fiber.Map{
		"imageBedType":    "s3",
		"s3SignMode":      mode,
		"s3PublicBaseURL": s.PublicBaseURL,
		"s3KeyPrefix":     s.KeyPrefix,
		"imagePageSize":   userImagePageSize(u),
	}
	if mode == "client" {
		m["s3Endpoint"] = s.Endpoint
		m["s3Region"] = s.Region
		m["s3Bucket"] = s.Bucket
		m["s3AccessKey"] = s.AccessKey
		m["s3SecretKey"] = s.SecretKey
		m["s3UseSSL"] = s.UseSSL
		m["s3PathStyle"] = s.PathStyle
	}
	return c.JSON(types.OkItem(m))
}

// PresignImage (server sign mode only) returns a short-lived presigned PUT URL
// the browser uploads the image bytes to, plus the public URL to embed. The
// `name` form value is the desired object path under the bed's key prefix
// (the original filename, or "album/filename" when an album is chosen); it is
// preserved (sanitized) so the stored object keeps its filename.
func (h *Handler) PresignImage(c *fiber.Ctx) error {
	u, err := h.loadUser(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrRe("未登录"))
	}
	if userImageBedType(u) != "s3" || userS3SignMode(u) != "server" {
		return c.JSON(types.ErrRe("图床未启用服务端签名"))
	}
	s := userS3Config(u)
	if !s.Valid() {
		return c.JSON(types.ErrRe("S3 配置不完整"))
	}
	key := s.BuildKey(c.FormValue("name"))
	uploadURL, err := s.PresignPut(key, 5*time.Minute)
	if err != nil {
		return c.JSON(types.ErrRe("生成上传链接失败"))
	}
	return c.JSON(types.OkItem(fiber.Map{
		"uploadUrl": uploadURL,
		"publicUrl": s.PublicURL(key),
		"key":       key,
	}))
}

// BedImages lists the active S3 bed for the image browser. Distinct key
// prefixes (CommonPrefixes, via delimiter "/") are returned as albums; objects
// directly under `prefix` are returned with their public URL. `prefix` defaults
// to the bed's key prefix (top level); `token` is a continuation token for
// "load more". This is the only call that reaches S3 from the server, and it
// transfers object keys, not image bytes.
func (h *Handler) BedImages(c *fiber.Ctx) error {
	u, err := h.loadUser(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrRe("未登录"))
	}
	if userImageBedType(u) != "s3" {
		return c.JSON(types.ErrRe("图床未启用"))
	}
	s := userS3Config(u)
	if !s.Valid() {
		return c.JSON(types.ErrRe("S3 配置不完整"))
	}
	prefix := c.Query("prefix")
	if prefix == "" {
		prefix = strings.TrimLeft(s.KeyPrefix, "/")
	}
	// size bounds the page (max-keys). Default to the configured image page size;
	// the album sidebar passes a larger size to fetch all prefixes.
	size := userImagePageSize(u)
	if v, err := strconv.Atoi(c.Query("size")); err == nil && v > 0 {
		if v > 1000 {
			v = 1000
		}
		size = v
	}
	res, err := s.ListObjects(prefix, "/", c.Query("token"), size)
	if err != nil {
		return c.JSON(types.ErrRe("列举图床失败：" + err.Error()))
	}
	images := make([]fiber.Map, 0, len(res.Objects))
	for _, o := range res.Objects {
		if strings.HasSuffix(o.Key, "/") {
			continue // skip "folder" placeholder objects
		}
		images = append(images, fiber.Map{
			"key":  o.Key,
			"url":  s.PublicURL(o.Key),
			"size": o.Size,
		})
	}
	return c.JSON(types.OkItem(fiber.Map{
		"prefixes": res.CommonPrefixes,
		"images":   images,
		"next":     res.NextToken,
	}))
}

// ----- S3 bed management (delete object / album prefix ops) -----
// These run server-side with the active bed's stored credentials (works for both
// sign modes; bedImages already lists server-side). All guard that the target is
// within the bed's key prefix.

// activeS3 returns the current user's active bed S3 config when it is enabled
// and valid.
func (h *Handler) activeS3(c *fiber.Ctx) (imagebed.S3Config, bool) {
	u, err := h.loadUser(c)
	if err != nil {
		return imagebed.S3Config{}, false
	}
	if userImageBedType(u) != "s3" {
		return imagebed.S3Config{}, false
	}
	s := userS3Config(u)
	return s, s.Valid()
}

// underBase guards that a key/prefix sits inside the bed's key prefix.
func underBase(s imagebed.S3Config, key string) bool {
	base := strings.TrimLeft(s.KeyPrefix, "/")
	return key != "" && strings.HasPrefix(key, base) && !strings.Contains(key, "..")
}

// collectKeys lists every object key under prefix (no delimiter → recursive),
// following continuation tokens.
func collectKeys(s imagebed.S3Config, prefix string) ([]string, error) {
	var keys []string
	for token := ""; ; {
		res, err := s.ListObjects(prefix, "", token, 1000)
		if err != nil {
			return nil, err
		}
		for _, o := range res.Objects {
			keys = append(keys, o.Key)
		}
		if res.NextToken == "" {
			return keys, nil
		}
		token = res.NextToken
	}
}

// BedDeleteObject deletes one object from the bed.
func (h *Handler) BedDeleteObject(c *fiber.Ctx) error {
	s, ok := h.activeS3(c)
	if !ok {
		return c.JSON(types.ErrRe("图床未启用或配置不完整"))
	}
	key := c.FormValue("key")
	if !underBase(s, key) {
		return c.JSON(types.ErrRe("非法的对象 key"))
	}
	if err := s.DeleteObject(key); err != nil {
		return c.JSON(types.ErrRe("删除失败：" + err.Error()))
	}
	return c.JSON(types.OkRe())
}

// BedCreatePrefix creates an empty album (a placeholder object under the prefix).
func (h *Handler) BedCreatePrefix(c *fiber.Ctx) error {
	s, ok := h.activeS3(c)
	if !ok {
		return c.JSON(types.ErrRe("图床未启用或配置不完整"))
	}
	name := strings.Trim(strings.TrimSpace(c.FormValue("name")), "/")
	if name == "" || strings.Contains(name, "..") {
		return c.JSON(types.ErrRe("相册名不合法"))
	}
	key := strings.TrimLeft(s.KeyPrefix, "/") + name + "/.keep"
	if err := s.PutEmpty(key); err != nil {
		return c.JSON(types.ErrRe("新建失败：" + err.Error()))
	}
	return c.JSON(types.OkRe())
}

// BedDeletePrefix deletes an album: every object under the prefix.
func (h *Handler) BedDeletePrefix(c *fiber.Ctx) error {
	s, ok := h.activeS3(c)
	if !ok {
		return c.JSON(types.ErrRe("图床未启用或配置不完整"))
	}
	prefix := c.FormValue("prefix")
	if !underBase(s, prefix) {
		return c.JSON(types.ErrRe("非法前缀"))
	}
	keys, err := collectKeys(s, prefix)
	if err != nil {
		return c.JSON(types.ErrRe("列举失败：" + err.Error()))
	}
	for _, k := range keys {
		_ = s.DeleteObject(k)
	}
	return c.JSON(types.OkItem(fiber.Map{"deleted": len(keys)}))
}

// BedRenamePrefix renames an album by copying every object to the new prefix and
// deleting the old (S3 has no native folder rename — slow for big albums).
func (h *Handler) BedRenamePrefix(c *fiber.Ctx) error {
	s, ok := h.activeS3(c)
	if !ok {
		return c.JSON(types.ErrRe("图床未启用或配置不完整"))
	}
	old := c.FormValue("oldPrefix")
	newName := strings.Trim(strings.TrimSpace(c.FormValue("newName")), "/")
	if !underBase(s, old) || newName == "" || strings.Contains(newName, "..") {
		return c.JSON(types.ErrRe("参数不合法"))
	}
	if !strings.HasSuffix(old, "/") {
		old += "/"
	}
	newPrefix := strings.TrimLeft(s.KeyPrefix, "/") + newName + "/"
	keys, err := collectKeys(s, old)
	if err != nil {
		return c.JSON(types.ErrRe("列举失败：" + err.Error()))
	}
	moved := 0
	for _, k := range keys {
		dst := newPrefix + strings.TrimPrefix(k, old)
		if err := s.CopyObject(k, dst); err != nil {
			continue
		}
		_ = s.DeleteObject(k)
		moved++
	}
	return c.JSON(types.OkItem(fiber.Map{"moved": moved}))
}
