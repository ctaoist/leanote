package handler

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"leanote/internal/models"
	"leanote/internal/oid"
	"leanote/internal/types"
	"leanote/internal/web"
)

// blogSortFields whitelists the fields a blog may be sorted by (mirrors the
// columns leanote orders blog post lists on).
var blogSortFields = map[string]bool{
	"CreatedTime": true, "UpdatedTime": true, "PublicTime": true,
	"Title": true, "ReadNum": true, "LikeNum": true,
}

// ----- blog settings (per-user, stored in user_blogs, _id=userId) -----

// BlogSettings returns the current user's blog settings (base/comment/paging),
// plus the active theme's name. Missing fields fall back to sensible defaults.
func (h *Handler) BlogSettings(c *fiber.Ctx) error {
	u, err := h.loadUser(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrRe("未登录"))
	}
	ctx := c.Context()
	var b models.UserBlog
	_ = h.DB.UserBlogs.FindOne(ctx, bson.M{"_id": u.UserId}).Decode(&b)

	title := b.Title
	if title == "" {
		title = u.Email + " 's blog"
	}
	commentType := b.CommentType
	if commentType == "" {
		commentType = "default"
	}
	perPage := b.PerPageSize
	if perPage < 1 {
		perPage = 10
	}
	sortField := b.SortField
	if sortField == "" {
		sortField = "PublicTime"
	}
	blogType := b.BlogType
	if blogType == "" {
		blogType = "dynamic"
	}

	themeName := ""
	if !b.ThemeId.IsZero() {
		var t models.Theme
		if h.DB.Themes.FindOne(ctx, bson.M{"_id": b.ThemeId}).Decode(&t) == nil {
			themeName = t.Name
		}
	}

	return c.JSON(types.OkItem(fiber.Map{
		"Title":       title,
		"SubTitle":    b.SubTitle,
		"AboutMe":     b.AboutMe,
		"Logo":        b.Logo,
		"CanComment":  b.CanComment,
		"CommentType": commentType,
		"DisqusId":    b.DisqusId,
		"PerPageSize": perPage,
		"SortField":   sortField,
		"IsAsc":       b.IsAsc,
		"ThemeId":     b.ThemeId,
		"ThemeName":   themeName,
		"BlogType":    blogType,
		"SubDomain":   b.SubDomain,
		"Domain":      b.Domain,
		// Read-only: the admin-configured base domain, so the UI can render the
		// resulting "<sub>.<base>" address. Empty means subdomain blogs are off.
		"BlogBaseDomain": h.Cfg.BlogBaseDomain,
	}))
}

// UpdateBlogSettings upserts whichever blog-settings fields were submitted into
// user_blogs. It is a partial $set so unmanaged fields (CateIds, Singles, theme
// state, custom domains) are preserved. Validation runs before any write.
func (h *Handler) UpdateBlogSettings(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	if uid.IsZero() {
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrRe("未登录"))
	}
	set := bson.M{}
	for _, f := range []string{"Title", "SubTitle", "AboutMe", "DisqusId"} {
		if web.Has(c, f) {
			set[f] = strings.TrimSpace(c.FormValue(f))
		}
	}
	if web.Has(c, "CanComment") {
		set["CanComment"] = formBool(c, "CanComment")
	}
	if web.Has(c, "IsAsc") {
		set["IsAsc"] = formBool(c, "IsAsc")
	}
	if web.Has(c, "CommentType") {
		v := strings.TrimSpace(c.FormValue("CommentType"))
		if v != "default" && v != "disqus" {
			return c.JSON(types.ErrRe("评论类型不合法"))
		}
		set["CommentType"] = v
	}
	if web.Has(c, "BlogType") {
		v := strings.TrimSpace(c.FormValue("BlogType"))
		if v != "dynamic" && v != "static" {
			return c.JSON(types.ErrRe("博客类型不合法"))
		}
		set["BlogType"] = v
	}
	if web.Has(c, "SortField") {
		v := strings.TrimSpace(c.FormValue("SortField"))
		if !blogSortFields[v] {
			return c.JSON(types.ErrRe("排序字段不合法"))
		}
		set["SortField"] = v
	}
	if web.Has(c, "PerPageSize") {
		n, err := strconv.Atoi(strings.TrimSpace(c.FormValue("PerPageSize")))
		if err != nil || n < 1 {
			return c.JSON(types.ErrRe("每页篇数必须为正整数"))
		}
		set["PerPageSize"] = n
	}

	// Host-routing fields: a SubDomain (single DNS label) and/or a bound custom
	// Domain. Both are normalized to lowercase, validated, checked for cross-user
	// uniqueness, and cleared via $unset when submitted empty.
	unset := bson.M{}
	if web.Has(c, "SubDomain") {
		sub := strings.ToLower(strings.TrimSpace(c.FormValue("SubDomain")))
		switch {
		case sub == "":
			unset["SubDomain"] = ""
		case !validSubDomain(sub):
			return c.JSON(types.ErrRe("子域名只能含小写字母、数字、连字符，且不能以连字符开头或结尾"))
		case reservedSub[sub]:
			return c.JSON(types.ErrRe("该子域名为系统保留，请换一个"))
		default:
			taken, err := h.blogFieldTaken(c.Context(), "SubDomain", sub, uid)
			if err != nil {
				return c.JSON(types.ErrRe("保存失败"))
			}
			if taken {
				return c.JSON(types.ErrRe("该子域名已被占用"))
			}
			set["SubDomain"] = sub
		}
	}
	if web.Has(c, "Domain") {
		dom := strings.ToLower(strings.TrimSpace(c.FormValue("Domain")))
		switch {
		case dom == "":
			unset["Domain"] = ""
		case !validDomain(dom) || dom == h.Cfg.AppHost || dom == h.Cfg.BlogBaseDomain:
			return c.JSON(types.ErrRe("独立域名格式不正确"))
		default:
			taken, err := h.blogFieldTaken(c.Context(), "Domain", dom, uid)
			if err != nil {
				return c.JSON(types.ErrRe("保存失败"))
			}
			if taken {
				return c.JSON(types.ErrRe("该域名已被占用"))
			}
			set["Domain"] = dom
		}
	}

	update := bson.M{}
	if len(set) > 0 {
		update["$set"] = set
	}
	if len(unset) > 0 {
		update["$unset"] = unset
	}
	if len(update) > 0 {
		if _, err := h.DB.UserBlogs.UpdateOne(c.Context(), bson.M{"_id": uid},
			update, options.Update().SetUpsert(true)); err != nil {
			return c.JSON(types.ErrRe("保存失败"))
		}
	}
	return c.JSON(types.OkRe())
}

// ----- themes (per-user, file-based; existing leanote `themes`) -----

// findUserTheme loads a theme owned by the current user, by hex id.
func (h *Handler) findUserTheme(c *fiber.Ctx, idHex string) (models.Theme, bool) {
	tid, ok := oid.Parse(idHex)
	if !ok {
		return models.Theme{}, false
	}
	uid := web.UserOID(c)
	var t models.Theme
	if h.DB.Themes.FindOne(c.Context(), bson.M{"_id": tid, "UserId": uid}).Decode(&t) != nil {
		return models.Theme{}, false
	}
	return t, true
}

// Themes lists the current user's themes (active first).
func (h *Handler) Themes(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	themes := []models.Theme{}
	cur, err := h.DB.Themes.Find(c.Context(), bson.M{"UserId": uid},
		options.Find().SetSort(bson.D{{Key: "IsActive", Value: -1}, {Key: "CreatedTime", Value: 1}}))
	if err == nil {
		_ = cur.All(c.Context(), &themes)
	}
	return c.JSON(types.OkItem(themes))
}

// ActiveTheme sets the user's active theme (themes.IsActive + user_blogs.ThemeId/Path).
func (h *Handler) ActiveTheme(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	t, ok := h.findUserTheme(c, c.FormValue("themeId"))
	if !ok {
		return c.JSON(types.ErrRe("主题不存在"))
	}
	ctx := c.Context()
	_, _ = h.DB.Themes.UpdateMany(ctx, bson.M{"UserId": uid, "IsActive": true},
		bson.M{"$set": bson.M{"IsActive": false}})
	_, _ = h.DB.Themes.UpdateOne(ctx, bson.M{"_id": t.ThemeId},
		bson.M{"$set": bson.M{"IsActive": true}})
	_, _ = h.DB.UserBlogs.UpdateOne(ctx, bson.M{"_id": uid},
		bson.M{"$set": bson.M{"ThemeId": t.ThemeId, "ThemePath": t.Path}},
		options.Update().SetUpsert(true))
	return c.JSON(types.OkRe())
}

// DeleteTheme removes a non-active theme (DB doc + on-disk directory).
func (h *Handler) DeleteTheme(c *fiber.Ctx) error {
	t, ok := h.findUserTheme(c, c.FormValue("themeId"))
	if !ok {
		return c.JSON(types.ErrRe("主题不存在"))
	}
	if t.IsActive {
		return c.JSON(types.ErrRe("当前使用中的主题不可删除"))
	}
	if _, err := h.DB.Themes.DeleteOne(c.Context(), bson.M{"_id": t.ThemeId}); err != nil {
		return c.JSON(types.ErrRe("删除失败"))
	}
	_ = h.Store.RemoveThemeDir(t.Path)
	return c.JSON(types.OkRe())
}

// ThemeFiles lists a theme's editable files (theme-relative paths).
func (h *Handler) ThemeFiles(c *fiber.Ctx) error {
	t, ok := h.findUserTheme(c, c.Query("themeId"))
	if !ok {
		return c.JSON(types.ErrRe("主题不存在"))
	}
	files, err := h.Store.ListThemeFiles(t.Path)
	if err != nil {
		return c.JSON(types.ErrRe("读取主题失败"))
	}
	return c.JSON(types.OkItem(files))
}

// ThemeFile returns one theme file's content.
func (h *Handler) ThemeFile(c *fiber.Ctx) error {
	t, ok := h.findUserTheme(c, c.Query("themeId"))
	if !ok {
		return c.JSON(types.ErrRe("主题不存在"))
	}
	data, err := h.Store.ReadThemeFile(t.Path, c.Query("filename"))
	if err != nil {
		return c.JSON(types.ErrRe("读取文件失败"))
	}
	return c.JSON(types.OkItem(string(data)))
}

// UpdateThemeFile writes a theme file. .html files get a best-effort Go-template
// syntax check (leanote theme funcs aren't registered here, so undefined-function
// errors are tolerated); theme.json is validated as JSON and its Name/Author/
// Version/Info are synced into the theme document.
func (h *Handler) UpdateThemeFile(c *fiber.Ctx) error {
	t, ok := h.findUserTheme(c, c.FormValue("themeId"))
	if !ok {
		return c.JSON(types.ErrRe("主题不存在"))
	}
	filename := c.FormValue("filename")
	content := c.FormValue("content")

	if strings.HasSuffix(strings.ToLower(filename), ".html") {
		if err := validateTemplateSyntax(filename, content); err != nil {
			return c.JSON(types.ErrRe("模板语法错误：" + err.Error()))
		}
	}
	if filename == "theme.json" {
		info, err := parseThemeConfig([]byte(content))
		if err != nil {
			return c.JSON(types.ErrRe("theme.json 不合法：" + err.Error()))
		}
		upd := bson.M{"Info": info, "UpdatedTime": time.Now()}
		for _, k := range []string{"Name", "Author", "AuthorUrl", "Version"} {
			if v, ok := info[k].(string); ok {
				upd[k] = v
			}
		}
		_, _ = h.DB.Themes.UpdateOne(c.Context(), bson.M{"_id": t.ThemeId}, bson.M{"$set": upd})
	}
	if err := h.Store.WriteThemeFile(t.Path, filename, []byte(content)); err != nil {
		return c.JSON(types.ErrRe("保存失败：" + err.Error()))
	}
	return c.JSON(types.OkRe())
}

// DeleteThemeFile removes one file from a theme.
func (h *Handler) DeleteThemeFile(c *fiber.Ctx) error {
	t, ok := h.findUserTheme(c, c.FormValue("themeId"))
	if !ok {
		return c.JSON(types.ErrRe("主题不存在"))
	}
	if err := h.Store.RemoveThemeFile(t.Path, c.FormValue("filename")); err != nil {
		return c.JSON(types.ErrRe("删除失败"))
	}
	return c.JSON(types.OkRe())
}

// UploadThemeImage stores an uploaded image under the theme's images/ folder.
func (h *Handler) UploadThemeImage(c *fiber.Ctx) error {
	t, ok := h.findUserTheme(c, c.FormValue("themeId"))
	if !ok {
		return c.JSON(types.ErrRe("主题不存在"))
	}
	data, filename, err := readUpload(c)
	if err != nil || len(data) == 0 {
		return c.JSON(types.ErrRe("没有文件"))
	}
	ext := strings.ToLower(filepath.Ext(filename))
	if !isImageExt(ext) {
		return c.JSON(types.ErrRe("请上传图片"))
	}
	if h.overSize(c.Context(), cfgUploadImageSize, int64(len(data))) {
		return c.JSON(types.ErrRe("图片超过大小限制"))
	}
	name := filepath.Base(filename)
	if err := h.Store.WriteThemeFile(t.Path, "images/"+name, data); err != nil {
		return c.JSON(types.ErrRe("保存失败"))
	}
	return c.JSON(types.OkItem(fiber.Map{"name": name}))
}

// ImportTheme unzips an uploaded .zip into a new theme directory and creates the
// theme document from its theme.json. The zip must contain theme.json at its root.
func (h *Handler) ImportTheme(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	data, _, err := readUpload(c)
	if err != nil || len(data) == 0 {
		return c.JSON(types.ErrRe("没有文件"))
	}
	tid := oid.New()
	themePath, err := h.Store.MakeThemeDir(uid.Hex(), tid.Hex())
	if err != nil {
		return c.JSON(types.ErrRe("创建主题目录失败"))
	}
	absBase, err := h.Store.ThemeDirAbs(themePath)
	if err != nil {
		_ = h.Store.RemoveThemeDir(themePath)
		return c.JSON(types.ErrRe("主题路径不合法"))
	}
	if err := unzipTheme(absBase, data); err != nil {
		_ = h.Store.RemoveThemeDir(themePath)
		return c.JSON(types.ErrRe("解压失败：" + err.Error()))
	}
	cfg, err := h.Store.ReadThemeFile(themePath, "theme.json")
	if err != nil {
		_ = h.Store.RemoveThemeDir(themePath)
		return c.JSON(types.ErrRe("压缩包内缺少 theme.json"))
	}
	info, err := parseThemeConfig(cfg)
	if err != nil {
		_ = h.Store.RemoveThemeDir(themePath)
		return c.JSON(types.ErrRe("theme.json 不合法：" + err.Error()))
	}
	name, _ := info["Name"].(string)
	if strings.TrimSpace(name) == "" {
		_ = h.Store.RemoveThemeDir(themePath)
		return c.JSON(types.ErrRe("theme.json 缺少 Name"))
	}
	theme := models.Theme{
		ThemeId:     tid,
		UserId:      uid,
		Name:        name,
		Path:        themePath,
		Info:        info,
		CreatedTime: time.Now(),
		UpdatedTime: time.Now(),
	}
	if v, ok := info["Author"].(string); ok {
		theme.Author = v
	}
	if v, ok := info["AuthorUrl"].(string); ok {
		theme.AuthorUrl = v
	}
	if v, ok := info["Version"].(string); ok {
		theme.Version = v
	}
	if _, err := h.DB.Themes.InsertOne(c.Context(), theme); err != nil {
		_ = h.Store.RemoveThemeDir(themePath)
		return c.JSON(types.ErrRe("保存主题失败"))
	}
	return c.JSON(types.OkItem(fiber.Map{"themeId": tid.Hex(), "name": name}))
}

// ExportTheme streams a theme directory as a .zip download.
func (h *Handler) ExportTheme(c *fiber.Ctx) error {
	t, ok := h.findUserTheme(c, c.Query("themeId"))
	if !ok {
		return c.JSON(types.ErrRe("主题不存在"))
	}
	files, err := h.Store.ListThemeFiles(t.Path)
	if err != nil {
		return c.JSON(types.ErrRe("读取主题失败"))
	}
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	for _, f := range files {
		data, rerr := h.Store.ReadThemeFile(t.Path, f)
		if rerr != nil {
			continue
		}
		w, cerr := zw.Create(f)
		if cerr != nil {
			continue
		}
		_, _ = w.Write(data)
	}
	if err := zw.Close(); err != nil {
		return c.JSON(types.ErrRe("打包失败"))
	}
	name := t.Name
	if name == "" {
		name = "theme"
	}
	c.Set("Content-Type", "application/zip")
	c.Set("Content-Disposition", `attachment; filename="`+name+`.zip"`)
	return c.Send(buf.Bytes())
}

// validateTemplateSyntax does a best-effort Go-template parse. leanote theme
// templates call revel/leanote funcs that aren't registered here, so an
// "undefined function" parse error is treated as acceptable; other errors
// (unbalanced actions, bad pipelines) are reported.
func validateTemplateSyntax(name, content string) error {
	if _, err := template.New(name).Parse(content); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "not defined") || strings.Contains(msg, "function") {
			return nil
		}
		return err
	}
	return nil
}

// parseThemeConfig parses a theme.json that MAY contain comments (JSONC). The
// leanote theme.json files ship with a leading /* ... */ header block; we also
// tolerate // line comments. Stripping is string-aware so URLs inside string
// values (which contain "//") are preserved.
func parseThemeConfig(content []byte) (map[string]any, error) {
	var info map[string]any
	if err := json.Unmarshal(stripJSONComments(content), &info); err != nil {
		return nil, err
	}
	if info == nil {
		return nil, fiber.NewError(fiber.StatusBadRequest, "空配置")
	}
	return info, nil
}

// stripJSONComments removes // line comments and /* */ block comments from a
// JSON document, but only outside of string literals (so https:// URLs and other
// "//" inside strings survive). Escapes inside strings are honored.
func stripJSONComments(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			out = append(out, c)
			continue
		}
		if c == '/' && i+1 < len(b) {
			if b[i+1] == '/' { // line comment → skip to end of line
				i += 2
				for i < len(b) && b[i] != '\n' {
					i++
				}
				if i < len(b) {
					out = append(out, b[i]) // keep the newline
				}
				continue
			}
			if b[i+1] == '*' { // block comment → skip to */
				i += 2
				for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
					i++
				}
				i++ // land on '/', outer i++ moves past it
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// unzipTheme extracts an uploaded theme .zip into destAbs. It tolerates archives
// that wrap everything in a single top folder (e.g. GitHub "Download ZIP"): the
// directory containing the shallowest theme.json becomes the theme root and that
// prefix is stripped. Guards against zip-slip; skips __MACOSX cruft.
func unzipTheme(destAbs string, data []byte) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	// locate the shallowest theme.json and take its directory as the root prefix.
	root := ""
	found := false
	bestDepth := 1 << 30
	for _, f := range zr.File {
		name := strings.TrimPrefix(filepath.ToSlash(f.Name), "./")
		if f.FileInfo().IsDir() || strings.Contains(name, "__MACOSX") {
			continue
		}
		if name == "theme.json" || strings.HasSuffix(name, "/theme.json") {
			if d := strings.Count(name, "/"); d < bestDepth {
				bestDepth = d
				root = strings.TrimSuffix(name, "theme.json") // "Chirpy/" or ""
				found = true
			}
		}
	}
	if !found {
		return fiber.NewError(fiber.StatusBadRequest, "压缩包内缺少 theme.json")
	}

	sep := string(filepath.Separator)
	for _, f := range zr.File {
		name := strings.TrimPrefix(filepath.ToSlash(f.Name), "./")
		if strings.Contains(name, "__MACOSX") {
			continue
		}
		if root != "" && !strings.HasPrefix(name, root) {
			continue // outside the theme root folder
		}
		rel := name[len(root):]
		if rel == "" || strings.Contains(rel, "..") {
			if strings.Contains(rel, "..") {
				return fiber.NewError(fiber.StatusBadRequest, "非法的压缩包条目")
			}
			continue
		}
		target := filepath.Join(destAbs, filepath.FromSlash(rel))
		if target != destAbs && !strings.HasPrefix(target, destAbs+sep) {
			return fiber.NewError(fiber.StatusBadRequest, "非法的压缩包条目")
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.Create(target)
		if err != nil {
			rc.Close()
			return err
		}
		_, cpErr := io.Copy(out, rc)
		out.Close()
		rc.Close()
		if cpErr != nil {
			return cpErr
		}
	}
	return nil
}
