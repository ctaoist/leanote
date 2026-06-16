// Static-blog deploy surface (all auth, per-user): read/update the GitHub Pages
// deploy config, publish (generate + git push), and download the generated site
// as a zip. Secrets (the PAT) are write-only — never returned to the client.
package handler

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"leanote/internal/blog"
	"leanote/internal/types"
	"leanote/internal/web"
)

// BlogDeploySettings returns the user's static-deploy config. The PAT is never
// returned — only a HasToken flag — and the derived public URL is included.
func (h *Handler) BlogDeploySettings(c *fiber.Ctx) error {
	owner, err := h.loadUser(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrRe("未登录"))
	}
	ub := h.Blog.ResolveUserBlog(c.Context(), owner)
	branch := ub.GhBranch
	if branch == "" {
		branch = "gh-pages"
	}
	return c.JSON(types.OkItem(fiber.Map{
		"BlogType":   ub.BlogType,
		"GhRepo":     ub.GhRepo,
		"GhBranch":   branch,
		"GhDomain":   ub.GhDomain,
		"GhBasePath": ub.GhBasePath,
		"GhEmail":    ub.GhEmail,
		"HasToken":   ub.GhToken != "",
		"LastDeploy": ub.LastDeploy,
		"PublicURL":  deployedURL(owner, ub),
	}))
}

// UpdateBlogDeploySettings upserts the deploy config (partial $set). GhToken is
// written only when a non-empty value is submitted, so saving other fields keeps
// the stored token.
func (h *Handler) UpdateBlogDeploySettings(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	if uid.IsZero() {
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrRe("未登录"))
	}
	set := bson.M{}
	for _, f := range []string{"GhRepo", "GhBranch", "GhDomain", "GhEmail"} {
		if web.Has(c, f) {
			set[f] = strings.TrimSpace(c.FormValue(f))
		}
	}
	if web.Has(c, "GhBasePath") {
		bp := strings.TrimSpace(c.FormValue("GhBasePath"))
		if bp != "" && !strings.HasPrefix(bp, "/") {
			bp = "/" + bp
		}
		set["GhBasePath"] = strings.TrimRight(bp, "/")
	}
	if web.Has(c, "GhToken") {
		if tok := strings.TrimSpace(c.FormValue("GhToken")); tok != "" {
			set["GhToken"] = tok
		}
	}
	if repo, ok := set["GhRepo"].(string); ok && repo != "" && strings.Count(repo, "/") != 1 {
		return c.JSON(types.ErrRe("仓库格式应为 owner/name"))
	}
	if len(set) > 0 {
		if _, err := h.DB.UserBlogs.UpdateOne(c.Context(), bson.M{"_id": uid},
			bson.M{"$set": set}, options.Update().SetUpsert(true)); err != nil {
			return c.JSON(types.ErrRe("保存失败"))
		}
	}
	return c.JSON(types.OkRe())
}

// PublishBlog generates the static site and force-pushes it to GitHub Pages.
func (h *Handler) PublishBlog(c *fiber.Ctx) error {
	owner, err := h.loadUser(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrRe("未登录"))
	}
	ub := h.Blog.ResolveUserBlog(c.Context(), owner)
	if ub.GhRepo == "" {
		return c.JSON(types.ErrRe("请先填写 GitHub 仓库（owner/name）"))
	}
	if ub.GhToken == "" {
		return c.JSON(types.ErrRe("请先填写 GitHub Token"))
	}
	tmp, err := os.MkdirTemp("", "leanote-blog-*")
	if err != nil {
		return c.JSON(types.ErrRe("创建临时目录失败"))
	}
	defer os.RemoveAll(tmp)

	site := deployedURL(owner, ub)
	pages, err := h.Blog.GenerateSite(c.Context(), owner, tmp, blog.StaticOpts{BasePath: ub.GhBasePath, SiteURL: site})
	if err != nil {
		return c.JSON(types.ErrRe("生成站点失败：" + err.Error()))
	}
	summary, err := h.Blog.DeployGitHub(c.Context(), tmp, blog.GhConfig{
		Repo: ub.GhRepo, Branch: ub.GhBranch, Token: ub.GhToken,
		Domain: ub.GhDomain, Name: owner.Username, Email: ub.GhEmail,
	})
	if err != nil {
		return c.JSON(types.ErrRe("部署失败：" + err.Error()))
	}
	now := time.Now()
	_, _ = h.DB.UserBlogs.UpdateOne(c.Context(), bson.M{"_id": owner.UserId},
		bson.M{"$set": bson.M{"LastDeploy": now}})
	return c.JSON(types.OkItem(fiber.Map{
		"Summary": summary, "Pages": pages, "PublicURL": site, "LastDeploy": now,
	}))
}

// DownloadBlogZip generates the static site and streams it back as a .zip (the
// no-token fallback for manual deploys).
func (h *Handler) DownloadBlogZip(c *fiber.Ctx) error {
	owner, err := h.loadUser(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrRe("未登录"))
	}
	ub := h.Blog.ResolveUserBlog(c.Context(), owner)
	tmp, err := os.MkdirTemp("", "leanote-blog-*")
	if err != nil {
		return c.JSON(types.ErrRe("创建临时目录失败"))
	}
	defer os.RemoveAll(tmp)
	site := deployedURL(owner, ub)
	if _, err := h.Blog.GenerateSite(c.Context(), owner, tmp, blog.StaticOpts{BasePath: ub.GhBasePath, SiteURL: site}); err != nil {
		return c.JSON(types.ErrRe("生成站点失败：" + err.Error()))
	}
	buf, err := zipDir(tmp)
	if err != nil {
		return c.JSON(types.ErrRe("打包失败：" + err.Error()))
	}
	c.Set("Content-Type", "application/zip")
	c.Set("Content-Disposition", `attachment; filename="blog-static.zip"`)
	return c.Send(buf.Bytes())
}

// zipDir zips a directory tree (relative paths), skipping the .git dir.
func zipDir(dir string) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil || rel == "." {
			return rerr
		}
		if strings.HasPrefix(filepath.ToSlash(rel), ".git/") || rel == ".git" {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}
		w, cerr := zw.Create(filepath.ToSlash(rel))
		if cerr != nil {
			return cerr
		}
		f, oerr := os.Open(path)
		if oerr != nil {
			return oerr
		}
		defer f.Close()
		_, copyErr := io.Copy(w, f)
		return copyErr
	})
	if err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf, nil
}
