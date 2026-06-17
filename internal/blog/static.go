package blog

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"leanote/internal/models"
	"leanote/internal/oid"
)

// StaticOpts configures static-site generation.
type StaticOpts struct {
	BasePath string // URL path prefix: "" (root/custom domain) or "/repo" (project page)
	SiteURL  string // absolute site URL for RSS/sitemap links (e.g. https://user.github.io/repo)
}

// staticIndexCap bounds how many posts/items the generator iterates (post pages,
// tags, RSS) — a safety ceiling, not real pagination (the index is paginated).
const staticIndexCap = 100000

// rewriteStaticPaging converts the theme's query-string paging links
// (<basePath>/?page=N) into clean static paths: page 1 → <basePath>/, page N →
// <basePath>/page/N/. Applied to each generated index page.
func rewriteStaticPaging(html, basePath string) string {
	re := regexp.MustCompile(regexp.QuoteMeta(basePath+"/") + `\?page=(\d+)`)
	return re.ReplaceAllStringFunc(html, func(m string) string {
		n := re.FindStringSubmatch(m)[1]
		if n == "1" {
			return basePath + "/"
		}
		return basePath + "/page/" + n + "/"
	})
}

// GenerateSite renders the user's whole blog into outDir as a static site:
// index, every post, archives, tags (+ per tag), cates (+ per cate), singles,
// 404, rss.xml, sitemap.xml; copies the theme's assets to /theme and any local
// post images to /assets/img; writes .nojekyll. Returns the page count.
func (r *Renderer) GenerateSite(ctx context.Context, owner models.User, outDir string, opts StaticOpts) (int, error) {
	ub := r.ResolveUserBlog(ctx, owner)
	theme, themeDir, err := r.resolveTheme(ctx, owner, ub)
	if err != nil {
		return 0, err
	}
	base := strings.TrimRight(opts.BasePath, "/")
	imgs := map[string]string{}
	pages := 0

	writePage := func(rel string, req PageReq) error {
		var buf bytes.Buffer
		if rerr := r.RenderStatic(ctx, &buf, owner, base, imgs, req); rerr != nil {
			if rerr == ErrNotFound {
				return nil // skip missing optional pages
			}
			return fmt.Errorf("render %s: %w", rel, rerr)
		}
		full := filepath.Join(outDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, buf.Bytes(), 0o644); err != nil {
			return err
		}
		pages++
		return nil
	}

	// index, paginated: page 1 → index.html, pages 2..N → page/N/index.html.
	// The theme builds paging links as <base>/?page=N (urlConcat); rewrite those
	// to clean /page/N/ dirs so they work on a static host.
	paging1, _ := r.ListBlogs(ctx, owner.UserId, mustOID(""), 1, ub.PerPageSize, ub.SortField, ub.IsAsc, true)
	totalPage := paging1.TotalPage
	if totalPage < 1 {
		totalPage = 1
	}
	for p := 1; p <= totalPage; p++ {
		var buf bytes.Buffer
		if rerr := r.RenderStatic(ctx, &buf, owner, base, imgs, PageReq{Type: "index", Page: p}); rerr != nil {
			return pages, fmt.Errorf("render index page %d: %w", p, rerr)
		}
		out := rewriteStaticPaging(buf.String(), base)
		rel := "index.html"
		if p > 1 {
			rel = fmt.Sprintf("page/%d/index.html", p)
		}
		full := filepath.Join(outDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return pages, err
		}
		if err := os.WriteFile(full, []byte(out), 0o644); err != nil {
			return pages, err
		}
		pages++
	}

	// every post
	_, posts := r.ListBlogs(ctx, owner.UserId, mustOID(""), 1, staticIndexCap, ub.SortField, ub.IsAsc, true)
	for _, p := range posts {
		rel := "post/" + slugPath(p.UrlTitle) + "/index.html"
		if err := writePage(rel, PageReq{Type: "post", Id: p.UrlTitle}); err != nil {
			return pages, err
		}
	}

	// archives / tags / cates
	_ = writePage("archives/index.html", PageReq{Type: "archives"})
	_ = writePage("tags/index.html", PageReq{Type: "tags"})
	for _, t := range r.BlogTags(ctx, owner.UserId) {
		_ = writePage("tag/"+slugPath(t.Tag)+"/index.html", PageReq{Type: "tag", Tag: t.Tag})
	}
	_ = writePage("cates/index.html", PageReq{Type: "cates"})
	for _, seg := range r.allCateSegs(ctx, owner.UserId) {
		_ = writePage("cate/"+slugPath(seg)+"/index.html", PageReq{Type: "cate", CateId: seg})
	}

	// single pages
	for _, s := range r.Singles(ctx, ub) {
		idOrUrl := s["UrlTitle"]
		if idOrUrl == "" {
			idOrUrl = s["SingleId"]
		}
		_ = writePage("single/"+slugPath(idOrUrl)+"/index.html", PageReq{Type: "single", Id: idOrUrl})
	}

	// 404 (best effort — theme may lack 404.html)
	_ = writePage("404.html", PageReq{Type: "404"})

	// search page: the theme's search.html rendered with all posts (a no-JS
	// browse fallback) plus injected Pagefind glue that queries the index built
	// below. Best-effort — themes without search.html are skipped.
	if r.generateSearch(ctx, owner, base, imgs, outDir) {
		pages++
	}

	// RSS + sitemap
	siteURL := opts.SiteURL
	if siteURL == "" {
		siteURL = base
	}
	postBase := strings.TrimRight(siteURL, "/") + "/post"
	if err := os.WriteFile(filepath.Join(outDir, "rss.xml"), []byte(r.RSS(ctx, owner, ub, siteURL, postBase)), 0o644); err != nil {
		return pages, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "sitemap.xml"), []byte(r.Sitemap(ctx, owner, ub, postBase)), 0o644); err != nil {
		return pages, err
	}

	// copy theme assets (everything except *.html and theme.json) → /theme
	if err := copyThemeAssets(themeDir, filepath.Join(outDir, "theme")); err != nil {
		return pages, err
	}
	_ = theme // theme metadata already applied via ViewArgs

	// copy local post images → /assets/img
	if len(imgs) > 0 {
		imgDir := filepath.Join(outDir, "assets", "img")
		if err := os.MkdirAll(imgDir, 0o755); err == nil {
			for id, ext := range imgs {
				r.copyLocalImage(ctx, id, ext, imgDir)
			}
		}
	}

	// Full-text search index (Pagefind) built from a clean per-post corpus.
	// Best-effort: a missing/failed indexer leaves the search page's browse
	// fallback intact (the glue shows a "reindex" notice).
	if err := r.buildSearchIndex(ctx, owner, base, outDir); err != nil {
		fmt.Printf("blog: pagefind index skipped: %v\n", err)
	}

	// GitHub Pages: don't run the output through Jekyll.
	_ = os.WriteFile(filepath.Join(outDir, ".nojekyll"), []byte{}, 0o644)
	return pages, nil
}

// allCateSegs returns the URL segment (UrlTitle, hex-fallback) for every category
// notebook (top-level + sub) that has posts — matching the {{cateUrl}}/{{.UrlTitle}}
// links the themes emit, so static cate dirs line up with the in-page links.
func (r *Renderer) allCateSegs(ctx context.Context, uid oid.OID) []string {
	segs := []string{}
	for _, c := range r.Cates(ctx, uid) {
		if s, _ := c["UrlTitle"].(string); s != "" {
			segs = append(segs, s)
		}
		if subs, ok := c["SubCates"].([]map[string]any); ok {
			for _, s := range subs {
				if seg, _ := s["UrlTitle"].(string); seg != "" {
					segs = append(segs, seg)
				}
			}
		}
	}
	return segs
}

// slugPath turns a UrlTitle/tag into a safe single path segment for the static
// tree: it URL-decodes (so the on-disk dir matches the decoded request path) and
// strips path separators / traversal.
func slugPath(s string) string {
	if dec, err := url.PathUnescape(s); err == nil {
		s = dec
	}
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "\\", "-")
	s = strings.ReplaceAll(s, "..", "-")
	s = strings.TrimSpace(s)
	if s == "" {
		s = "untitled"
	}
	return s
}

// copyThemeAssets copies a theme directory's non-template files into dst,
// preserving structure (skips *.html, theme.json, and any .git directory).
func copyThemeAssets(srcDir, dst string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(srcDir, path)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		// skip VCS metadata
		parts := strings.Split(filepath.ToSlash(rel), "/")
		for _, p := range parts {
			if p == ".git" {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		low := strings.ToLower(info.Name())
		if strings.HasSuffix(low, ".html") || low == "theme.json" {
			return nil
		}
		return copyFile(path, filepath.Join(dst, rel))
	})
}

// copyLocalImage copies an image file (by fileId) into dst as <id><ext>.
func (r *Renderer) copyLocalImage(ctx context.Context, idHex, ext, dst string) {
	o, ok := oid.Parse(idHex)
	if !ok {
		return
	}
	var f models.File
	if err := r.DB.Files.FindOne(ctx, bson.M{"_id": o}).Decode(&f); err != nil || f.Path == "" {
		return
	}
	abs, err := r.Store.Abs(f.Path)
	if err != nil {
		return
	}
	_ = copyFile(abs, filepath.Join(dst, idHex+ext))
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// ----- Pagefind static full-text search -----

// generateSearch renders the theme's search.html with all posts (a no-JS browse
// fallback that also matches the theme's look) and injects the Pagefind glue
// script that runs the actual client-side query. Returns whether the page was
// written (false when the theme has no search.html).
func (r *Renderer) generateSearch(ctx context.Context, owner models.User, base string, imgs map[string]string, outDir string) bool {
	var buf bytes.Buffer
	if err := r.RenderStatic(ctx, &buf, owner, base, imgs, PageReq{Type: "search", PerPage: -1}); err != nil {
		return false
	}
	page := injectPagefind(buf.String(), base)
	full := filepath.Join(outDir, "search", "index.html")
	if os.MkdirAll(filepath.Dir(full), 0o755) != nil {
		return false
	}
	return os.WriteFile(full, []byte(page), 0o644) == nil
}

// injectPagefind appends the Pagefind glue module before the page's closing
// </body> (or at the end if there is none).
func injectPagefind(page, base string) string {
	script := "\n<script type=\"module\">" + strings.ReplaceAll(pagefindGlue, "__BASE__", base) + "</script>\n"
	if i := strings.LastIndex(page, "</body>"); i >= 0 {
		return page[:i] + script + page[i:]
	}
	return page + script
}

// buildSearchIndex builds a clean per-post corpus (article text only, carrying
// the real post URL in metadata) in a temp dir and runs Pagefind over it, writing
// the index into outDir/pagefind. Indexing the themed pages directly would
// pollute every document with the shared sidebar/tag-cloud; the dedicated corpus
// keeps ranking clean and is theme-agnostic. Best-effort: returns nil (skips)
// when the pagefind binary is absent; returns an error only when indexing was
// attempted and failed.
func (r *Renderer) buildSearchIndex(ctx context.Context, owner models.User, base, outDir string) error {
	bin := r.pagefindBinary()
	if bin == "" {
		return nil // no indexer available — leave the browse fallback in place
	}
	ub := r.ResolveUserBlog(ctx, owner)
	_, posts := r.ListBlogs(ctx, owner.UserId, oid.OID{}, 1, staticIndexCap, ub.SortField, ub.IsAsc, true)
	if len(posts) == 0 {
		return nil
	}
	ids := make([]oid.OID, 0, len(posts))
	for _, p := range posts {
		if o, ok := oid.Parse(p.NoteId); ok {
			ids = append(ids, o)
		}
	}
	contents := r.noteContents(ctx, ids)

	corpus, err := os.MkdirTemp("", "leanote-pfsrc-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(corpus)

	for i, p := range posts {
		body := ""
		if nc, ok := contents[p.NoteId]; ok {
			body = nc.Content
		}
		realURL := base + "/post/" + slugPath(p.UrlTitle) + "/"
		doc := corpusDoc(p.Title, realURL, plainText(body))
		dir := filepath.Join(corpus, fmt.Sprintf("%d", i))
		if os.MkdirAll(dir, 0o755) != nil {
			continue
		}
		_ = os.WriteFile(filepath.Join(dir, "index.html"), []byte(doc), 0o644)
	}

	out := filepath.Join(outDir, "pagefind")
	cmd := exec.CommandContext(ctx, bin, "--site", corpus, "--output-path", out)
	if b, cerr := cmd.CombinedOutput(); cerr != nil {
		return fmt.Errorf("%s: %v: %s", filepath.Base(bin), cerr, strings.TrimSpace(string(b)))
	}
	return nil
}

// pagefindBinary resolves the Pagefind CLI: the configured path/name if set and
// found, otherwise "pagefind_extended" then "pagefind" on PATH. Returns "" when
// none is available (indexing is then skipped).
func (r *Renderer) pagefindBinary() string {
	if b := strings.TrimSpace(r.Cfg.PagefindBin); b != "" {
		if filepath.IsAbs(b) {
			if _, err := os.Stat(b); err == nil {
				return b
			}
		}
		if p, err := exec.LookPath(b); err == nil {
			return p
		}
		return ""
	}
	for _, name := range []string{"pagefind_extended", "pagefind"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// corpusDoc builds one minimal indexable HTML doc: the title (as Pagefind's title
// metadata and inside the body so title terms match), the real post URL captured
// into the "link" metadata, and the plain-text article body.
func corpusDoc(title, realURL, body string) string {
	t := html.EscapeString(title)
	u := html.EscapeString(realURL)
	b := html.EscapeString(title + "\n" + body)
	return "<!doctype html><html lang=\"zh\"><head><meta charset=\"utf-8\"><title>" + t +
		"</title></head><body>\n<h1 data-pagefind-meta=\"title\">" + t + "</h1>\n" +
		"<a data-pagefind-meta=\"link[href]\" href=\"" + u + "\" hidden></a>\n" +
		"<div data-pagefind-body>" + b + "</div>\n</body></html>"
}

var (
	rePfHTMLTag = regexp.MustCompile(`<[^>]+>`)
	rePfMdImage = regexp.MustCompile(`!\[[^\]]*\]\([^)]*\)`)
	rePfMdLink  = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
	rePfMdMarks = regexp.MustCompile("[`*_>#~|]+")
	rePfSpace   = regexp.MustCompile(`\s+`)
)

// plainText reduces a note's markdown/HTML content to searchable plain text: it
// drops HTML tags and image syntax, keeps link text (drops the target), strips
// common markdown markers, and collapses whitespace. Capped at a generous rune
// ceiling so one pathologically long post can't bloat the corpus.
func plainText(s string) string {
	s = rePfHTMLTag.ReplaceAllString(s, " ")
	s = rePfMdImage.ReplaceAllString(s, " ")
	s = rePfMdLink.ReplaceAllString(s, "$1")
	s = rePfMdMarks.ReplaceAllString(s, " ")
	s = rePfSpace.ReplaceAllString(s, " ")
	s = strings.TrimSpace(s)
	const maxRunes = 100000
	if rs := []rune(s); len(rs) > maxRunes {
		s = string(rs[:maxRunes])
	}
	return s
}

// pagefindGlue is the client-side search module injected into search/index.html.
// __BASE__ is replaced with the site base path. It reads ?keywords=, queries the
// Pagefind index, and renders results into #search-results (with the all-posts
// render preserved as the empty-query / no-JS fallback). It also wires the
// theme's #search-input for live search.
const pagefindGlue = `/* leanote-pagefind */
(function () {
  var PF_BASE = "__BASE__";
  var box = document.getElementById("search-results");
  if (!box) return;
  var input = document.getElementById("search-input");
  var original = box.innerHTML;
  var pf = null, loadErr = false, timer = null;

  function esc(s) {
    return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function note(msg) {
    box.innerHTML = '<p class="text-muted mt-3" style="text-align:center">' + esc(msg) + "</p>";
  }
  async function ensure() {
    if (pf) return pf;
    pf = await import(PF_BASE + "/pagefind/pagefind.js");
    if (pf.options) { try { await pf.options({ baseUrl: PF_BASE + "/" }); } catch (e) {} }
    return pf;
  }
  function render(items) {
    if (!items.length) { note("没有找到匹配的文章"); return; }
    box.innerHTML = items.map(function (d) {
      var url = (d.meta && d.meta.link) || d.url || "#";
      var title = (d.meta && d.meta.title) || "(无标题)";
      return '<div class="pl-1 pr-1 pl-sm-2 pr-sm-2 pl-lg-4 pr-lg-4 pl-xl-0 pr-xl-0">' +
        '<a href="' + esc(url) + '">' + esc(title) + "</a><p>" + (d.excerpt || "") + "</p></div>";
    }).join("");
  }
  async function run(q) {
    q = (q || "").trim();
    if (!q) { box.innerHTML = original; return; }
    if (loadErr) { note("搜索索引未生成，请重新发布博客"); return; }
    try {
      var p = await ensure();
      var s = await p.search(q);
      var items = await Promise.all(s.results.slice(0, 30).map(function (r) { return r.data(); }));
      render(items);
    } catch (e) { loadErr = true; note("搜索索引未生成，请重新发布博客"); }
  }
  var params = new URLSearchParams(location.search);
  var kw = params.get("keywords") || params.get("keyword") || params.get("q") || "";
  if (input && kw && !input.value) input.value = kw;
  if (input) {
    input.addEventListener("input", function () {
      clearTimeout(timer);
      timer = setTimeout(function () { run(input.value); }, 150);
    });
  }
  if (kw) run(kw);
})();`

// ----- GitHub Pages deploy -----

// GhConfig is the deploy target. Token is a PAT and is scrubbed from all output.
type GhConfig struct {
	Repo   string // owner/name
	Branch string // gh-pages by default
	Token  string
	Domain string // CNAME (optional)
	Name   string // committer name
	Email  string // committer email
}

// buildRemote constructs the authenticated push URL. It is a package var so
// tests can point deploys at a local bare repo (file://) instead of github.com.
var buildRemote = func(repo, token string) string {
	return fmt.Sprintf("https://%s@github.com/%s.git", token, repo)
}

// DeployGitHub publishes siteDir to a GitHub Pages branch via git: it inits a
// repo in siteDir, commits everything, and force-pushes to the configured
// branch. The PAT is embedded in the push URL and scrubbed from any returned
// output. Returns a short human-readable summary.
func (r *Renderer) DeployGitHub(ctx context.Context, siteDir string, gh GhConfig) (string, error) {
	if strings.Count(gh.Repo, "/") != 1 || strings.HasPrefix(gh.Repo, "/") || strings.HasSuffix(gh.Repo, "/") {
		return "", fmt.Errorf("仓库格式应为 owner/name")
	}
	if gh.Token == "" {
		return "", fmt.Errorf("缺少 GitHub Token")
	}
	branch := gh.Branch
	if branch == "" {
		branch = "gh-pages"
	}
	name := gh.Name
	if name == "" {
		name = "leanote-blog"
	}
	email := gh.Email
	if email == "" {
		email = "leanote-blog@users.noreply.github.com"
	}

	// CNAME for custom domains.
	if gh.Domain != "" {
		_ = os.WriteFile(filepath.Join(siteDir, "CNAME"), []byte(gh.Domain+"\n"), 0o644)
	}

	remote := buildRemote(gh.Repo, gh.Token)
	scrub := func(s string) string {
		if gh.Token == "" {
			return s
		}
		return strings.ReplaceAll(s, gh.Token, "***")
	}

	run := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", siteDir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_TERMINAL_PROMPT=0", // never prompt for credentials
			"GIT_AUTHOR_NAME="+name, "GIT_AUTHOR_EMAIL="+email,
			"GIT_COMMITTER_NAME="+name, "GIT_COMMITTER_EMAIL="+email,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return scrub(string(out)), fmt.Errorf("git %s: %v: %s", scrub(strings.Join(args, " ")), err, scrub(string(out)))
		}
		return string(out), nil
	}

	steps := [][]string{
		{"init", "-q", "-b", branch},
		{"config", "user.name", name},
		{"config", "user.email", email},
		{"add", "-A"},
		{"commit", "-q", "-m", "deploy " + time.Now().Format("2006-01-02 15:04:05")},
		{"remote", "add", "origin", remote},
		{"push", "-f", "origin", branch},
	}
	for _, s := range steps {
		if _, err := run(s...); err != nil {
			return "", err
		}
	}
	rev, _ := run("rev-parse", "--short", "HEAD")
	return fmt.Sprintf("已推送到 %s 的 %s 分支 (commit %s)", gh.Repo, branch, strings.TrimSpace(rev)), nil
}
