// Public blog delivery: the live /blog/<user> routes (no auth, only when the
// user's BlogType is "dynamic"), the owner-only preview (any mode), the public
// blog-image passthrough, and RSS/sitemap. All rendering goes through the shared
// internal/blog engine.
package handler

import (
	"bytes"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"

	"leanote/internal/blog"
	"leanote/internal/models"
	"leanote/internal/oid"
)

// blogUserSeg is the URL segment used in a user's public blog links.
func blogUserSeg(u models.User) string {
	if u.Username != "" {
		return u.Username
	}
	if u.Email != "" {
		return u.Email
	}
	return u.UserId.Hex()
}

// blogOwner resolves the :userIdOrEmail path segment to a user. Empty resolves
// to the configured admin user (so bare /blog works).
func (h *Handler) blogOwner(c *fiber.Ctx, seg string) (models.User, bool) {
	ctx := c.Context()
	if seg == "" {
		return h.findUserByName(ctx, h.Cfg.AdminUsername)
	}
	if u, ok := h.findUserByName(ctx, seg); ok {
		return u, true
	}
	if o, ok := oid.Parse(seg); ok {
		var u models.User
		if err := h.DB.Users.FindOne(ctx, bson.M{"_id": o}).Decode(&u); err == nil {
			return u, true
		}
	}
	return models.User{}, false
}

// servePublic renders a public blog page, honoring the strict static-mode gate.
func (h *Handler) servePublic(c *fiber.Ctx, owner models.User, req blog.PageReq) error {
	ub := h.Blog.ResolveUserBlog(c.Context(), owner)
	if ub.BlogType == "static" {
		return h.blogStaticNotice(c, owner, ub)
	}
	var buf bytes.Buffer
	if err := h.Blog.RenderPublic(c.Context(), &buf, owner, blogUserSeg(owner), req); err != nil {
		return h.blogError(c, owner, false, err)
	}
	c.Set("Content-Type", "text/html; charset=utf-8")
	return c.Send(buf.Bytes())
}

// servePreview renders a page of the logged-in user's own blog (any mode).
func (h *Handler) servePreview(c *fiber.Ctx, req blog.PageReq) error {
	owner, err := h.loadUser(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).Type("html").SendString("<h1>请先登录</h1>")
	}
	var buf bytes.Buffer
	if rerr := h.Blog.RenderPreview(c.Context(), &buf, owner, req); rerr != nil {
		return h.blogError(c, owner, true, rerr)
	}
	c.Set("Content-Type", "text/html; charset=utf-8")
	return c.Send(buf.Bytes())
}

// blogError maps a render error to the theme's 404 (or a plain fallback).
func (h *Handler) blogError(c *fiber.Ctx, owner models.User, preview bool, err error) error {
	c.Status(fiber.StatusNotFound)
	if err == blog.ErrNoTheme {
		return c.Type("html").SendString("<h1>博客未配置主题</h1><p>请在「设置 → 博客设置」中导入并启用一个主题。</p>")
	}
	var buf bytes.Buffer
	var e2 error
	if preview {
		e2 = h.Blog.RenderPreview(c.Context(), &buf, owner, blog.PageReq{Type: "404"})
	} else {
		e2 = h.Blog.RenderPublic(c.Context(), &buf, owner, blogUserSeg(owner), blog.PageReq{Type: "404"})
	}
	if e2 == nil {
		c.Set("Content-Type", "text/html; charset=utf-8")
		return c.Send(buf.Bytes())
	}
	return c.Type("html").SendString("<h1>404 Not Found</h1>")
}

// blogStaticNotice is shown for a static-mode blog hit on the live route: it
// points visitors at the deployed GitHub Pages site.
func (h *Handler) blogStaticNotice(c *fiber.Ctx, owner models.User, ub models.UserBlog) error {
	link := deployedURL(owner, ub)
	body := "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>" + html(ub.Title) + "</title></head>" +
		"<body style=\"font-family:sans-serif;max-width:640px;margin:80px auto;padding:0 20px;line-height:1.6\">" +
		"<h1>" + html(ub.Title) + "</h1><p>该博客为<strong>静态部署</strong>模式。</p>"
	if link != "" {
		body += "<p>请访问已部署的站点：<a href=\"" + html(link) + "\">" + html(link) + "</a></p>"
	} else {
		body += "<p>站点尚未部署。</p>"
	}
	body += "</body></html>"
	return c.Type("html").SendString(body)
}

// deployedURL derives the public URL of a static blog (custom domain, else the
// GitHub Pages URL inferred from owner/repo).
func deployedURL(owner models.User, ub models.UserBlog) string {
	if ub.GhDomain != "" {
		return "https://" + ub.GhDomain
	}
	if ub.GhRepo == "" {
		return ""
	}
	parts := strings.Split(ub.GhRepo, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	user, name := parts[0], parts[1]
	if name == user+".github.io" {
		return "https://" + name + "/"
	}
	return "https://" + user + ".github.io/" + name + "/"
}

// html minimally escapes a string for the static-notice page.
func html(s string) string {
	r := ""
	for _, c := range s {
		switch c {
		case '<':
			r += "&lt;"
		case '>':
			r += "&gt;"
		case '&':
			r += "&amp;"
		case '"':
			r += "&quot;"
		default:
			r += string(c)
		}
	}
	return r
}

// ----- public route handlers -----

func (h *Handler) BlogIndex(c *fiber.Ctx) error {
	owner, ok := h.blogOwner(c, c.Params("userIdOrEmail"))
	if !ok {
		return c.Status(fiber.StatusNotFound).Type("html").SendString("<h1>博客不存在</h1>")
	}
	return h.servePublic(c, owner, blog.PageReq{Type: "index", Page: c.QueryInt("page", 1)})
}

func (h *Handler) BlogPost(c *fiber.Ctx) error {
	seg := c.Params("userIdOrEmail")
	noteId := c.Params("noteId")
	// /blog/post/:noteId form: the single param is the note id.
	if noteId == "" {
		noteId = seg
		seg = ""
	}
	owner, ok := h.blogOwner(c, seg)
	if !ok {
		return c.Status(fiber.StatusNotFound).Type("html").SendString("<h1>博客不存在</h1>")
	}
	return h.servePublic(c, owner, blog.PageReq{Type: "post", Id: noteId})
}

func (h *Handler) BlogCate(c *fiber.Ctx) error {
	owner, ok := h.blogOwner(c, c.Params("userIdOrEmail"))
	if !ok {
		return c.Status(fiber.StatusNotFound).Type("html").SendString("<h1>博客不存在</h1>")
	}
	return h.servePublic(c, owner, blog.PageReq{Type: "cate", CateId: c.Params("notebookId")})
}

func (h *Handler) BlogCates(c *fiber.Ctx) error {
	owner, ok := h.blogOwner(c, c.Params("userIdOrEmail"))
	if !ok {
		return c.Status(fiber.StatusNotFound).Type("html").SendString("<h1>博客不存在</h1>")
	}
	return h.servePublic(c, owner, blog.PageReq{Type: "cates"})
}

func (h *Handler) BlogTags(c *fiber.Ctx) error {
	owner, ok := h.blogOwner(c, c.Params("userIdOrEmail"))
	if !ok {
		return c.Status(fiber.StatusNotFound).Type("html").SendString("<h1>博客不存在</h1>")
	}
	return h.servePublic(c, owner, blog.PageReq{Type: "tags"})
}

func (h *Handler) BlogTag(c *fiber.Ctx) error {
	owner, ok := h.blogOwner(c, c.Params("userIdOrEmail"))
	if !ok {
		return c.Status(fiber.StatusNotFound).Type("html").SendString("<h1>博客不存在</h1>")
	}
	tag, _ := decodeParam(c.Params("tag"))
	return h.servePublic(c, owner, blog.PageReq{Type: "tag", Tag: tag})
}

func (h *Handler) BlogArchives(c *fiber.Ctx) error {
	owner, ok := h.blogOwner(c, c.Params("userIdOrEmail"))
	if !ok {
		return c.Status(fiber.StatusNotFound).Type("html").SendString("<h1>博客不存在</h1>")
	}
	return h.servePublic(c, owner, blog.PageReq{Type: "archives"})
}

func (h *Handler) BlogSearch(c *fiber.Ctx) error {
	owner, ok := h.blogOwner(c, c.Params("userIdOrEmail"))
	if !ok {
		return c.Status(fiber.StatusNotFound).Type("html").SendString("<h1>博客不存在</h1>")
	}
	kw := c.Query("keywords")
	if kw == "" {
		kw, _ = decodeParam(c.Params("keywords"))
	}
	return h.servePublic(c, owner, blog.PageReq{Type: "search", Keyword: kw, Page: c.QueryInt("page", 1)})
}

func (h *Handler) BlogSingle(c *fiber.Ctx) error {
	owner, ok := h.blogOwner(c, c.Params("userIdOrEmail"))
	if !ok {
		return c.Status(fiber.StatusNotFound).Type("html").SendString("<h1>博客不存在</h1>")
	}
	return h.servePublic(c, owner, blog.PageReq{Type: "single", Id: c.Params("singleId")})
}

// BlogImage streams a blog post's local image to anonymous visitors (the dynamic
// counterpart to the static export's assets/img copy). Public by design — blog
// images are meant to be world-readable.
func (h *Handler) BlogImage(c *fiber.Ctx) error {
	fileID, ok := oid.Parse(c.Params("fileId"))
	if !ok {
		return c.SendStatus(fiber.StatusNotFound)
	}
	var file models.File
	if err := h.DB.Files.FindOne(c.Context(), bson.M{"_id": fileID}).Decode(&file); err != nil || file.Path == "" {
		return c.SendStatus(fiber.StatusNotFound)
	}
	abs, err := h.Store.Abs(file.Path)
	if err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}
	return c.SendFile(abs)
}

func (h *Handler) BlogRSS(c *fiber.Ctx) error {
	owner, ok := h.blogOwner(c, c.Params("userIdOrEmail"))
	if !ok {
		return c.SendStatus(fiber.StatusNotFound)
	}
	ub := h.Blog.ResolveUserBlog(c.Context(), owner)
	site := c.Protocol() + "://" + c.Hostname()
	postBase := site + "/blog/post/" + blogUserSeg(owner)
	c.Set("Content-Type", "application/xml; charset=utf-8")
	return c.SendString(h.Blog.RSS(c.Context(), owner, ub, site, postBase))
}

func (h *Handler) BlogSitemap(c *fiber.Ctx) error {
	owner, ok := h.blogOwner(c, c.Params("userIdOrEmail"))
	if !ok {
		return c.SendStatus(fiber.StatusNotFound)
	}
	ub := h.Blog.ResolveUserBlog(c.Context(), owner)
	site := c.Protocol() + "://" + c.Hostname()
	postBase := site + "/blog/post/" + blogUserSeg(owner)
	c.Set("Content-Type", "application/xml; charset=utf-8")
	return c.SendString(h.Blog.Sitemap(c.Context(), owner, ub, postBase))
}

// ----- preview route handlers (auth, owner-only) -----

func (h *Handler) BlogPreviewIndex(c *fiber.Ctx) error {
	return h.servePreview(c, blog.PageReq{Type: "index", Page: c.QueryInt("page", 1)})
}
func (h *Handler) BlogPreviewPost(c *fiber.Ctx) error {
	return h.servePreview(c, blog.PageReq{Type: "post", Id: c.Params("noteId")})
}
func (h *Handler) BlogPreviewCate(c *fiber.Ctx) error {
	return h.servePreview(c, blog.PageReq{Type: "cate", CateId: c.Params("notebookId")})
}
func (h *Handler) BlogPreviewCates(c *fiber.Ctx) error {
	return h.servePreview(c, blog.PageReq{Type: "cates"})
}
func (h *Handler) BlogPreviewTags(c *fiber.Ctx) error {
	return h.servePreview(c, blog.PageReq{Type: "tags"})
}
func (h *Handler) BlogPreviewTag(c *fiber.Ctx) error {
	tag, _ := decodeParam(c.Params("tag"))
	return h.servePreview(c, blog.PageReq{Type: "tag", Tag: tag})
}
func (h *Handler) BlogPreviewArchives(c *fiber.Ctx) error {
	return h.servePreview(c, blog.PageReq{Type: "archives"})
}
func (h *Handler) BlogPreviewSearch(c *fiber.Ctx) error {
	return h.servePreview(c, blog.PageReq{Type: "search", Keyword: c.Query("keywords"), Page: c.QueryInt("page", 1)})
}
func (h *Handler) BlogPreviewSingle(c *fiber.Ctx) error {
	return h.servePreview(c, blog.PageReq{Type: "single", Id: c.Params("singleId")})
}

// decodeParam URL-decodes a path param.
func decodeParam(s string) (string, error) {
	return url.PathUnescape(s)
}
