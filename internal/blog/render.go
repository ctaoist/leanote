package blog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"leanote/config"
	"leanote/internal/db"
	"leanote/internal/models"
	"leanote/internal/oid"
	"leanote/internal/storage"
)

// ErrNotFound is returned by Render when the requested post/single/category
// doesn't exist (handlers map it to the theme's 404). ErrNoTheme means the user
// has no active theme to render with.
var (
	ErrNotFound = errors.New("blog: not found")
	ErrNoTheme  = errors.New("blog: no active theme")
)

// Renderer renders a user's blog from their active theme. It is shared by the
// dynamic routes, the owner preview, and the static-site generator.
type Renderer struct {
	DB    *db.DB
	Store *storage.Store
	Cfg   config.Config
}

// NewRenderer builds a Renderer over the app's db/storage/config.
func NewRenderer(database *db.DB, store *storage.Store, cfg config.Config) *Renderer {
	return &Renderer{DB: database, Store: store, Cfg: cfg}
}

// renderEnv selects how a page is rendered: which URL scheme and how local
// images are rewritten. One of kind public|preview|static.
type renderEnv struct {
	kind     string            // "public" | "preview" | "static"
	userSeg  string            // username/email/id segment (public URLs)
	basePath string            // static site base path ("" or "/repo")
	imgMode  string            // "dynamic" | "static" | ""
	imgs     map[string]string // static: collected fileId -> ext to copy
}

// PageReq names the page to render and its parameters.
type PageReq struct {
	Type    string // index|post|archives|tags|tag|cates|cate|search|single
	Page    int
	PerPage int // override the blog's PerPageSize (0 = use default); static index lists all
	Id      string // post id/url-title, single id/url-title
	Tag     string
	Keyword string
	CateId  string
}

// ResolveUserBlog loads a user's blog settings with leanote's defaults applied.
func (r *Renderer) ResolveUserBlog(ctx context.Context, owner models.User) models.UserBlog {
	var ub models.UserBlog
	_ = r.DB.UserBlogs.FindOne(ctx, bson.M{"_id": owner.UserId}).Decode(&ub)
	if ub.Title == "" {
		ub.Title = owner.Email + " 's blog"
	}
	if ub.CommentType == "" {
		ub.CommentType = "default"
	}
	if ub.PerPageSize < 1 {
		ub.PerPageSize = 10
	}
	if ub.SortField == "" {
		ub.SortField = "PublicTime"
	}
	if ub.BlogType == "" {
		ub.BlogType = "dynamic"
	}
	return ub
}

// resolveTheme finds the user's active theme and its absolute on-disk directory.
func (r *Renderer) resolveTheme(ctx context.Context, owner models.User, ub models.UserBlog) (models.Theme, string, error) {
	var theme models.Theme
	if !ub.ThemeId.IsZero() {
		_ = r.DB.Themes.FindOne(ctx, bson.M{"_id": ub.ThemeId, "UserId": owner.UserId}).Decode(&theme)
	}
	if theme.Path == "" { // fall back to the user's active theme
		_ = r.DB.Themes.FindOne(ctx, bson.M{"UserId": owner.UserId, "IsActive": true},
			options.FindOne()).Decode(&theme)
	}
	if theme.Path == "" {
		return theme, "", ErrNoTheme
	}
	absDir, err := r.Store.Abs(theme.Path)
	if err != nil {
		return theme, "", err
	}
	return theme, absDir, nil
}

// urlsFor builds the URLConfig for an env given the resolved theme.
func (r *Renderer) urlsFor(env renderEnv, theme models.Theme) URLConfig {
	switch env.kind {
	case "static":
		return staticURLs(env.basePath)
	case "preview":
		return previewURLs("/" + theme.Path)
	case "host":
		return hostURLs("/" + theme.Path)
	default: // public
		return publicURLs(env.userSeg, "/"+theme.Path)
	}
}

// RenderPublic renders a page of owner's live blog (links use /blog/<userSeg>,
// local images route through /blog/image/<id>).
func (r *Renderer) RenderPublic(ctx context.Context, w io.Writer, owner models.User, userSeg string, req PageReq) error {
	return r.render(ctx, w, owner, renderEnv{kind: "public", userSeg: userSeg, imgMode: "dynamic"}, req)
}

// RenderPreview renders a page of owner's blog for the owner only, regardless of
// the blog's dynamic/static mode (links stay under /blog/preview).
func (r *Renderer) RenderPreview(ctx context.Context, w io.Writer, owner models.User, req PageReq) error {
	return r.render(ctx, w, owner, renderEnv{kind: "preview", imgMode: "dynamic"}, req)
}

// RenderHost renders a page of owner's live blog served on its own host
// (subdomain/custom domain): links are root-relative (no /blog/<user> prefix),
// local images still route through /blog/image/<id> (host-agnostic absolute).
func (r *Renderer) RenderHost(ctx context.Context, w io.Writer, owner models.User, req PageReq) error {
	return r.render(ctx, w, owner, renderEnv{kind: "host", imgMode: "dynamic"}, req)
}

// RenderStatic renders a page for the static site under basePath, rewriting local
// images to basePath/assets/img and recording them in imgs for copying.
func (r *Renderer) RenderStatic(ctx context.Context, w io.Writer, owner models.User, basePath string, imgs map[string]string, req PageReq) error {
	return r.render(ctx, w, owner, renderEnv{kind: "static", basePath: basePath, imgMode: "static", imgs: imgs}, req)
}

// render renders one blog page for owner into w. It resolves the user's blog +
// active theme, assembles ViewArgs, fills page-specific data, and executes the
// matching theme template. Output is buffered so a mid-render error never emits
// partial HTML.
func (r *Renderer) render(ctx context.Context, w io.Writer, owner models.User, env renderEnv, req PageReq) error {
	ub := r.ResolveUserBlog(ctx, owner)
	theme, absDir, err := r.resolveTheme(ctx, owner, ub)
	if err != nil {
		return err
	}
	urls := r.urlsFor(env, theme)
	args := r.buildCommon(ctx, owner, ub, theme, urls)

	uid := owner.UserId
	tmplName := ""
	switch req.Type {
	case "index":
		page := req.Page
		if page < 1 {
			page = 1
		}
		perPage := ub.PerPageSize
		if req.PerPage > 0 {
			perPage = req.PerPage
		}
		paging, posts := r.ListBlogs(ctx, uid, oid.OID{}, page, perPage, ub.SortField, ub.IsAsc, true)
		args["posts"] = posts
		args["paging"] = paging
		args["pagingBaseUrl"] = urls.IndexUrl
		args["curIsIndex"] = true
		tmplName = "index.html"

	case "post":
		post, ok := r.GetBlogByIdOrUrl(ctx, uid, req.Id)
		if !ok {
			return ErrNotFound
		}
		post.Content = r.rewriteImages(ctx, post.Content, &env)
		args["post"] = post
		args["curIsPost"] = true
		base := postTimeOf2(post, ub.SortField)
		pre, next := r.PreNextBlog(ctx, uid, ub.SortField, ub.IsAsc, mustOID(post.NoteId), base)
		if pre != nil {
			args["prePost"] = pre
		}
		if next != nil {
			args["nextPost"] = next
		}
		tmplName = "post.html"

	case "archives":
		args["archives"] = r.Archives(ctx, uid, ub.SortField, ub.IsAsc)
		args["curIsArchive"] = true
		tmplName = "archive.html"

	case "tags":
		args["curIsTags"] = true
		tmplName = "tags.html"

	case "tag":
		posts := r.SearchByTag(ctx, uid, req.Tag, ub.SortField, ub.IsAsc)
		args["posts"] = posts
		args["curTag"] = req.Tag
		args["curTagCount"] = len(posts)
		args["curIsTagPosts"] = true
		tmplName = "tag_posts.html"

	case "cates":
		args["curIsCates"] = true
		tmplName = "cates.html"

	case "cate":
		nb, ok := r.resolveCate(ctx, uid, req.CateId)
		if !ok {
			return ErrNotFound
		}
		args["posts"] = r.PostsByCate(ctx, uid, nb, ub.SortField, ub.IsAsc)
		args["curCateId"] = req.CateId
		args["curCateTitle"] = r.cateTitle(ctx, nb)
		args["curIsCate"] = true
		tmplName = "cate.html"

	case "search":
		page := req.Page
		if page < 1 {
			page = 1
		}
		paging, posts := r.SearchBlogs(ctx, uid, req.Keyword, page, ub.PerPageSize, ub.SortField, ub.IsAsc)
		args["posts"] = posts
		args["paging"] = paging
		args["keywords"] = req.Keyword
		args["pagingBaseUrl"] = urls.SearchUrl + "/" + req.Keyword
		args["curIsSearch"] = true
		tmplName = "search.html"

	case "single":
		single, ok := r.GetSingle(ctx, uid, req.Id)
		if !ok {
			return ErrNotFound
		}
		content := r.rewriteImages(ctx, single.Content, &env)
		args["single"] = map[string]any{
			"SingleId": single.SingleId.Hex(), "Title": single.Title,
			"UrlTitle": single.UrlTitle, "Content": content, "IsMarkdown": single.IsMarkdown,
		}
		args["curIsSingle"] = true
		tmplName = "single.html"

	case "404":
		tmplName = "404.html"

	default:
		return ErrNotFound
	}

	var buf bytes.Buffer
	if err := executeTemplate(absDir, tmplName, args, &buf); err != nil {
		return err
	}
	_, err = w.Write(buf.Bytes())
	return err
}

// executeTemplate loads the theme set and runs the named template, recovering
// from any panic a malformed theme might raise.
func executeTemplate(absDir, name string, args map[string]any, w io.Writer) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("blog: template %s panicked: %v", name, rec)
		}
	}()
	tpl, lerr := LoadTheme(absDir)
	if lerr != nil {
		return lerr
	}
	t := tpl.Lookup(name)
	if t == nil {
		return fmt.Errorf("blog: template %s not found in theme", name)
	}
	return t.Execute(w, args)
}

// cateTitle returns a notebook's title (for the category page heading).
func (r *Renderer) cateTitle(ctx context.Context, nb oid.OID) string {
	var n models.Notebook
	if err := r.DB.Notebooks.FindOne(ctx, bson.M{"_id": nb}).Decode(&n); err == nil {
		return n.Title
	}
	return ""
}

// postTimeOf2 returns the post's sort-field time (Post variant of postTimeOf).
func postTimeOf2(p *Post, sortField string) any {
	switch sortField {
	case "CreatedTime":
		return p.CreatedTime
	case "UpdatedTime":
		return p.UpdatedTime
	case "Title":
		return p.Title
	default:
		return p.PublicTime
	}
}

func mustOID(hex string) oid.OID {
	o, _ := oid.Parse(hex)
	return o
}
