package blog

import (
	"context"
	"strings"
	"time"

	"leanote/internal/models"
)

// RSS renders an RSS 2.0 feed of the user's latest posts. postURLBase is the
// absolute (or site-relative) prefix a post link is built on:
// postURLBase + "/" + UrlTitle. siteURL is the channel <link>.
func (r *Renderer) RSS(ctx context.Context, owner models.User, ub models.UserBlog, siteURL, postURLBase string) string {
	_, posts := r.ListBlogs(ctx, owner.UserId, mustOID(""), 1, ub.PerPageSize, "PublicTime", false, false)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString("<rss version=\"2.0\">\n<channel>\n")
	b.WriteString("  <title>" + xmlEscape(ub.Title) + "</title>\n")
	b.WriteString("  <link>" + xmlEscape(siteURL) + "</link>\n")
	b.WriteString("  <description>" + xmlEscape(ub.SubTitle) + "</description>\n")
	for _, p := range posts {
		link := postURLBase + "/" + p.UrlTitle
		b.WriteString("  <item>\n")
		b.WriteString("    <title>" + xmlEscape(p.Title) + "</title>\n")
		b.WriteString("    <link>" + xmlEscape(link) + "</link>\n")
		b.WriteString("    <description>" + xmlEscape(p.Desc) + "</description>\n")
		b.WriteString("    <pubDate>" + p.PublicTime.Format(time.RFC822) + "</pubDate>\n")
		b.WriteString("    <guid>" + xmlEscape(link) + "</guid>\n")
		b.WriteString("  </item>\n")
	}
	b.WriteString("</channel>\n</rss>")
	return b.String()
}

// Sitemap renders a sitemap.xml of all the user's posts.
func (r *Renderer) Sitemap(ctx context.Context, owner models.User, ub models.UserBlog, postURLBase string) string {
	_, posts := r.ListBlogs(ctx, owner.UserId, mustOID(""), 1, 50000, "PublicTime", false, false)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
	for _, p := range posts {
		link := postURLBase + "/" + p.UrlTitle + "/"
		if len(link) >= 2048 {
			continue
		}
		b.WriteString("  <url>\n")
		b.WriteString("    <loc>" + xmlEscape(link) + "</loc>\n")
		b.WriteString("    <lastmod>" + p.UpdatedTime.Format("2006-01-02") + "</lastmod>\n")
		b.WriteString("  </url>\n")
	}
	b.WriteString("</urlset>")
	return b.String()
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
