// Host-based blog delivery: a request to a user's blog subdomain
// (<sub>.<BlogBaseDomain>) or bound custom domain (UserBlog.Domain) is served at
// the host root — "/", "/post/<slug>", "/tag/<t>", … — with no /blog/<user>
// prefix. The main application host is left untouched (the middleware bails for
// it with no DB lookup). Rendering reuses the shared internal/blog engine via
// RenderHost (root-relative links).
package handler

import (
	"bytes"
	"context"
	"net"
	"regexp"
	"strings"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"

	"leanote/internal/blog"
	"leanote/internal/models"
	"leanote/internal/oid"
)

// reservedSub are subdomain labels that never map to a user blog (they belong to
// the app/infra), so "www.base", "api.base", … are treated as the app, not a
// blog lookup.
var reservedSub = map[string]bool{
	"www": true, "app": true, "api": true, "admin": true,
	"blog": true, "mail": true, "static": true, "cdn": true,
}

// stripPort removes a trailing :port from a host (IPv6-safe).
func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// isLocalOrIP reports whether host is localhost or a bare IP literal — never a
// blog host, so these short-circuit with no DB query.
func isLocalOrIP(host string) bool {
	return host == "localhost" || net.ParseIP(host) != nil
}

// Validation for user-set blog SubDomain / Domain. A SubDomain is a single DNS
// label; a Domain is a dotted hostname.
var (
	subDomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	domainRe    = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

func validSubDomain(s string) bool { return subDomainRe.MatchString(s) }
func validDomain(s string) bool    { return domainRe.MatchString(s) }

// blogFieldTaken reports whether another user's blog already uses field==value.
func (h *Handler) blogFieldTaken(ctx context.Context, field, value string, self oid.OID) (bool, error) {
	n, err := h.DB.UserBlogs.CountDocuments(ctx, bson.M{field: value, "_id": bson.M{"$ne": self}})
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// HostBlogMiddleware returns the Fiber middleware that serves blog hosts
// (subdomain / custom domain) at the host root, passing app hosts straight
// through. Exported so the router package can register it.
func (h *Handler) HostBlogMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if owner, ok := h.blogHostOwner(c); ok {
			return h.serveHost(c, owner)
		}
		return c.Next()
	}
}

// blogHostOwner resolves the request Host to a blog owner, or (zero,false) when
// the host is the main app (or unknown). It avoids any DB lookup for the common
// app-host cases. Subdomain blogs require cfg.BlogBaseDomain; custom-domain blogs
// work whenever a UserBlog.Domain matches.
func (h *Handler) blogHostOwner(c *fiber.Ctx) (models.User, bool) {
	host := stripPort(c.Hostname())
	if host == "" {
		return models.User{}, false
	}
	// Fast path: the app's own host, the base-domain apex, localhost, or a bare IP
	// are never blog hosts — bail with no DB lookup.
	if host == h.Cfg.AppHost || host == h.Cfg.BlogBaseDomain || isLocalOrIP(host) {
		return models.User{}, false
	}
	ctx := c.Context()

	// Subdomain blog: <sub>.<BlogBaseDomain> (single label, not reserved).
	if base := h.Cfg.BlogBaseDomain; base != "" {
		if sub, ok := strings.CutSuffix(host, "."+base); ok &&
			sub != "" && !strings.Contains(sub, ".") && !reservedSub[sub] {
			return h.userByBlogField(ctx, "SubDomain", sub)
		}
	}

	// Custom domain blog: an exact UserBlog.Domain match.
	return h.userByBlogField(ctx, "Domain", host)
}

// userByBlogField finds the user whose user_blogs document has field==value, then
// loads that user. (user_blogs._id is the userId.)
func (h *Handler) userByBlogField(ctx context.Context, field, value string) (models.User, bool) {
	var ub models.UserBlog
	if err := h.DB.UserBlogs.FindOne(ctx, bson.M{field: value}).Decode(&ub); err != nil {
		return models.User{}, false
	}
	if ub.UserId.IsZero() {
		return models.User{}, false
	}
	var u models.User
	if err := h.DB.Users.FindOne(ctx, bson.M{"_id": ub.UserId}).Decode(&u); err != nil {
		return models.User{}, false
	}
	return u, true
}

// serveHost dispatches a clean blog-host path to the renderer. Paths outside the
// blog URL scheme (/public/*, /blog/image/*, /file/*, /assets/*, SPA routes) and
// non-GET requests fall through to the normal handlers via c.Next().
func (h *Handler) serveHost(c *fiber.Ctx, owner models.User) error {
	if c.Method() != fiber.MethodGet {
		return c.Next()
	}
	p := c.Path()
	switch {
	case p == "/":
		return h.serveHostPage(c, owner, blog.PageReq{Type: "index", Page: c.QueryInt("page", 1)})
	case p == "/archives":
		return h.serveHostPage(c, owner, blog.PageReq{Type: "archives"})
	case p == "/tags":
		return h.serveHostPage(c, owner, blog.PageReq{Type: "tags"})
	case p == "/cates":
		return h.serveHostPage(c, owner, blog.PageReq{Type: "cates"})
	case p == "/search":
		return h.serveHostPage(c, owner, blog.PageReq{Type: "search", Keyword: c.Query("keywords"), Page: c.QueryInt("page", 1)})
	case p == "/rss.xml" || p == "/rss":
		return h.serveHostRSS(c, owner)
	case p == "/sitemap.xml":
		return h.serveHostSitemap(c, owner)
	case strings.HasPrefix(p, "/post/"):
		slug, _ := decodeParam(strings.TrimSuffix(strings.TrimPrefix(p, "/post/"), "/"))
		return h.serveHostPage(c, owner, blog.PageReq{Type: "post", Id: slug})
	case strings.HasPrefix(p, "/cate/"):
		nb := strings.TrimSuffix(strings.TrimPrefix(p, "/cate/"), "/")
		return h.serveHostPage(c, owner, blog.PageReq{Type: "cate", CateId: nb})
	case strings.HasPrefix(p, "/tag/"):
		tag, _ := decodeParam(strings.TrimSuffix(strings.TrimPrefix(p, "/tag/"), "/"))
		return h.serveHostPage(c, owner, blog.PageReq{Type: "tag", Tag: tag})
	case strings.HasPrefix(p, "/single/"):
		id := strings.TrimSuffix(strings.TrimPrefix(p, "/single/"), "/")
		return h.serveHostPage(c, owner, blog.PageReq{Type: "single", Id: id})
	default:
		return c.Next()
	}
}

// serveHostPage renders one host blog page, honoring the static-mode gate (a
// static-delivery blog points visitors at its deployed site, same as the
// /blog/<user> route).
func (h *Handler) serveHostPage(c *fiber.Ctx, owner models.User, req blog.PageReq) error {
	ub := h.Blog.ResolveUserBlog(c.Context(), owner)
	if ub.BlogType == "static" {
		return h.blogStaticNotice(c, owner, ub)
	}
	var buf bytes.Buffer
	if err := h.Blog.RenderHost(c.Context(), &buf, owner, req); err != nil {
		return h.blogErrorHost(c, owner, err)
	}
	c.Set("Content-Type", "text/html; charset=utf-8")
	return c.Send(buf.Bytes())
}

// blogErrorHost maps a render error to the theme's 404 (root-relative).
func (h *Handler) blogErrorHost(c *fiber.Ctx, owner models.User, err error) error {
	c.Status(fiber.StatusNotFound)
	if err == blog.ErrNoTheme {
		return c.Type("html").SendString("<h1>博客未配置主题</h1><p>请在「设置 → 博客设置」中导入并启用一个主题。</p>")
	}
	var buf bytes.Buffer
	if e2 := h.Blog.RenderHost(c.Context(), &buf, owner, blog.PageReq{Type: "404"}); e2 == nil {
		c.Set("Content-Type", "text/html; charset=utf-8")
		return c.Send(buf.Bytes())
	}
	return c.Type("html").SendString("<h1>404 Not Found</h1>")
}

// serveHostRSS / serveHostSitemap emit the feed/sitemap with absolute URLs rooted
// at this host (post links are <host>/post/<slug>).
func (h *Handler) serveHostRSS(c *fiber.Ctx, owner models.User) error {
	ub := h.Blog.ResolveUserBlog(c.Context(), owner)
	site := c.Protocol() + "://" + c.Hostname()
	c.Set("Content-Type", "application/xml; charset=utf-8")
	return c.SendString(h.Blog.RSS(c.Context(), owner, ub, site, site+"/post"))
}

func (h *Handler) serveHostSitemap(c *fiber.Ctx, owner models.User) error {
	ub := h.Blog.ResolveUserBlog(c.Context(), owner)
	site := c.Protocol() + "://" + c.Hostname()
	c.Set("Content-Type", "application/xml; charset=utf-8")
	return c.SendString(h.Blog.Sitemap(c.Context(), owner, ub, site+"/post"))
}
