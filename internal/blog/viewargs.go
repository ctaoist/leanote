package blog

import (
	"context"

	"leanote/internal/models"
)

// URLConfig holds every URL base a theme references. The three deliveries build
// it differently: public (/blog/<user>/…), preview (/blog/preview/…), and static
// (clean dir URLs under an optional base path).
type URLConfig struct {
	SiteUrl       string
	IndexUrl      string
	PostUrl       string
	CateUrl       string
	CatesUrl      string
	SearchUrl     string
	SingleUrl     string
	ArchiveUrl    string
	TagsUrl       string
	TagPostsUrl   string
	RSSUrl        string
	ThemeBaseUrl  string
	PagingBaseUrl string
}

// publicURLs builds the live /blog/<userIdOrEmail>/… URL set.
func publicURLs(userSeg, themeBaseUrl string) URLConfig {
	b := "/blog"
	return URLConfig{
		IndexUrl:     b + "/" + userSeg,
		PostUrl:      b + "/post/" + userSeg,
		CateUrl:      b + "/cate/" + userSeg,
		CatesUrl:     b + "/cates/" + userSeg,
		SearchUrl:    b + "/search/" + userSeg,
		SingleUrl:    b + "/single/" + userSeg,
		ArchiveUrl:   b + "/archives/" + userSeg,
		TagsUrl:      b + "/tags/" + userSeg,
		TagPostsUrl:  b + "/tag/" + userSeg,
		RSSUrl:       b + "/rss/" + userSeg,
		ThemeBaseUrl: themeBaseUrl,
	}
}

// previewURLs builds the owner-only /blog/preview/… URL set (no user segment;
// the preview handler scopes to the session user).
func previewURLs(themeBaseUrl string) URLConfig {
	b := "/blog/preview"
	return URLConfig{
		IndexUrl:     b,
		PostUrl:      b + "/post",
		CateUrl:      b + "/cate",
		CatesUrl:     b + "/cates",
		SearchUrl:    b + "/search",
		SingleUrl:    b + "/single",
		ArchiveUrl:   b + "/archives",
		TagsUrl:      b + "/tags",
		TagPostsUrl:  b + "/tag",
		RSSUrl:       b + "/rss",
		ThemeBaseUrl: themeBaseUrl,
	}
}

// staticURLs builds clean directory URLs for the static site under basePath
// ("" for a root/custom-domain site, "/repo" for a project page).
func staticURLs(basePath string) URLConfig {
	index := basePath + "/"
	return URLConfig{
		IndexUrl:     index,
		PostUrl:      basePath + "/post",
		CateUrl:      basePath + "/cate",
		CatesUrl:     basePath + "/cates",
		SearchUrl:    basePath + "/search/",
		SingleUrl:    basePath + "/single",
		ArchiveUrl:   basePath + "/archives",
		TagsUrl:      basePath + "/tags",
		TagPostsUrl:  basePath + "/tag",
		RSSUrl:       basePath + "/rss.xml",
		ThemeBaseUrl: basePath + "/theme",
	}
}

// hostURLs builds root-relative URLs for a blog served on its own host
// (subdomain or custom domain): the host already identifies the owner, so there
// is no /blog prefix and no user segment. Links sit at the domain root.
func hostURLs(themeBaseUrl string) URLConfig {
	return URLConfig{
		IndexUrl:     "/",
		PostUrl:      "/post",
		CateUrl:      "/cate",
		CatesUrl:     "/cates",
		SearchUrl:    "/search",
		SingleUrl:    "/single",
		ArchiveUrl:   "/archives",
		TagsUrl:      "/tags",
		TagPostsUrl:  "/tag",
		RSSUrl:       "/rss.xml",
		ThemeBaseUrl: themeBaseUrl,
	}
}

// buildCommon assembles the ViewArgs shared by every page (blogInfo, all URLs,
// themeInfo, recent posts/tags/singles/cates, locale, legacy asset URLs). Mirrors
// StaticBlogService.BlogCommon + SetBlogUrl + GetBlogInfo.
func (r *Renderer) buildCommon(ctx context.Context, owner models.User, ub models.UserBlog, theme models.Theme, urls URLConfig) map[string]any {
	uid := owner.UserId

	args := map[string]any{}

	// URLs.
	args["siteUrl"] = urls.SiteUrl
	args["indexUrl"] = urls.IndexUrl
	args["postUrl"] = urls.PostUrl
	args["cateUrl"] = urls.CateUrl
	args["catesUrl"] = urls.CatesUrl
	args["searchUrl"] = urls.SearchUrl
	args["singleUrl"] = urls.SingleUrl
	args["archiveUrl"] = urls.ArchiveUrl
	args["archivesUrl"] = urls.ArchiveUrl
	args["tagsUrl"] = urls.TagsUrl
	args["tagPostsUrl"] = urls.TagPostsUrl
	args["tagUrl"] = urls.TagPostsUrl
	args["rssUrl"] = urls.RSSUrl
	args["themeBaseUrl"] = urls.ThemeBaseUrl

	// Legacy static asset URLs (kept for older themes that reference them).
	args["jQueryUrl"] = "/public/libs/jquery/jquery.min.js"
	args["prettifyJsUrl"] = "/public/libs/google-code-prettify/prettify.js"
	args["prettifyCssUrl"] = "/public/libs/google-code-prettify/prettify.css"
	args["blogCommonJsUrl"] = "/public/blog/js/common.js"
	args["shareCommentCssUrl"] = "/public/blog/css/share_comment.css"
	args["shareCommentJsUrl"] = "/public/blog/js/share_comment.js"
	args["fontAwesomeUrl"] = "/public/libs/font-awesome-4.2.0/css/font-awesome.css"
	args["bootstrapCssUrl"] = "/public/libs/bootstrap/bootstrap.css"
	args["bootstrapJsUrl"] = "/public/libs/bootstrap/bootstrap-min.js"

	// Blog info.
	args["blogInfo"] = map[string]any{
		"UserId":      uid.Hex(),
		"Username":    owner.Username,
		"UserLogo":    owner.Logo,
		"Title":       ub.Title,
		"SubTitle":    ub.SubTitle,
		"Logo":        ub.Logo,
		"OpenComment": ub.CanComment,
		"CommentType": ub.CommentType,
		"DisqusId":    ub.DisqusId,
		"ThemeId":     ub.ThemeId.Hex(),
		"SubDomain":   ub.SubDomain,
		"Domain":      ub.Domain,
		"AboutMe":     ub.AboutMe,
	}

	// Sidebar data.
	args["recentPosts"] = r.RecentPosts(ctx, uid, 5)
	args["tags"] = r.BlogTags(ctx, uid)
	args["singles"] = r.Singles(ctx, ub)
	args["cates"] = r.Cates(ctx, uid)

	// Theme config (theme.json) + locale.
	if theme.Info != nil {
		args["themeInfo"] = theme.Info
	} else {
		args["themeInfo"] = map[string]any{}
	}
	args["locale"] = "zh"
	args[localeKey] = "zh"

	// Page-type flags default to false so {{if $.curIsX}} never errors.
	for _, k := range []string{"curIsIndex", "curIsPost", "curIsCate", "curIsCates",
		"curIsTags", "curIsTagPosts", "curIsArchive", "curIsSearch", "curIsSingle"} {
		args[k] = false
	}
	return args
}
