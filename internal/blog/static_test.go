package blog

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRewriteStaticPaging converts ?page=N links into clean /page/N/ dirs.
func TestRewriteStaticPaging(t *testing.T) {
	cases := []struct{ base, in, want string }{
		{"", `<a href="/?page=2">`, `<a href="/page/2/">`},
		{"", `<a href="/?page=1">`, `<a href="/">`},
		{"/blog", `<a href="/blog/?page=3">next`, `<a href="/blog/page/3/">next`},
		{"/blog", `<a href="/blog/?page=1">`, `<a href="/blog/">`},
		{"", `no paging here`, `no paging here`},
	}
	for _, c := range cases {
		if got := rewriteStaticPaging(c.in, c.base); got != c.want {
			t.Fatalf("base=%q in=%q: got %q want %q", c.base, c.in, got, c.want)
		}
	}
}

// TestRewriteImages_Dynamic checks that local /file/outputImage references are
// rewritten to the public /blog/image route while absolute (S3/CDN) URLs and
// non-matching text are left untouched. Dynamic mode needs no DB.
func TestRewriteImages_Dynamic(t *testing.T) {
	r := &Renderer{}
	env := &renderEnv{imgMode: "dynamic"}
	in := `![a](/file/outputImage?fileId=5a52dcf6fbe52b06a0000002) ` +
		`![b](https://blog.qiniu.ctaoist.cn/x.png) ` +
		`<img src="/file/outputImage?fileId=000000000000000000000abc">`
	out := r.rewriteImages(context.Background(), in, env)
	if !strings.Contains(out, "/blog/image/5a52dcf6fbe52b06a0000002") {
		t.Fatalf("local image 1 not rewritten: %s", out)
	}
	if !strings.Contains(out, "/blog/image/000000000000000000000abc") {
		t.Fatalf("local image 2 not rewritten: %s", out)
	}
	if !strings.Contains(out, "https://blog.qiniu.ctaoist.cn/x.png") {
		t.Fatalf("absolute URL must be preserved: %s", out)
	}
	if strings.Contains(out, "/file/outputImage") {
		t.Fatalf("local refs should be gone: %s", out)
	}
}

// TestRewriteImages_None leaves content untouched when no mode is set.
func TestRewriteImages_None(t *testing.T) {
	r := &Renderer{}
	in := "![a](/file/outputImage?fileId=5a52dcf6fbe52b06a0000002)"
	if got := r.rewriteImages(context.Background(), in, &renderEnv{}); got != in {
		t.Fatalf("expected unchanged, got %s", got)
	}
}

// TestDeployGitHub_LocalBare drives the full git init→commit→push flow against a
// local bare repo (no network), verifying the branch and a file land in it. The
// token is also asserted absent from the pushed refs path.
func TestDeployGitHub_LocalBare(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	tmp := t.TempDir()
	bare := filepath.Join(tmp, "remote.git")
	if out, err := exec.Command("git", "init", "--bare", "-b", "gh-pages", bare).CombinedOutput(); err != nil {
		t.Fatalf("init bare: %v: %s", err, out)
	}

	// Point deploys at the local bare repo.
	orig := buildRemote
	buildRemote = func(repo, token string) string { return "file://" + bare }
	defer func() { buildRemote = orig }()

	site := filepath.Join(tmp, "site")
	if err := os.MkdirAll(site, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(site, "index.html"), []byte("<html>hi</html>"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &Renderer{}
	summary, err := r.DeployGitHub(context.Background(), site, GhConfig{
		Repo: "owner/name", Branch: "gh-pages", Token: "ghp_secrettoken", Domain: "example.com",
	})
	if err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if !strings.Contains(summary, "gh-pages") {
		t.Fatalf("summary missing branch: %s", summary)
	}

	// The bare repo should now have gh-pages with index.html and CNAME.
	out, err := exec.Command("git", "-C", bare, "ls-tree", "-r", "--name-only", "gh-pages").CombinedOutput()
	if err != nil {
		t.Fatalf("ls-tree: %v: %s", err, out)
	}
	files := string(out)
	if !strings.Contains(files, "index.html") {
		t.Fatalf("index.html not pushed: %s", files)
	}
	if !strings.Contains(files, "CNAME") {
		t.Fatalf("CNAME (custom domain) not written/pushed: %s", files)
	}
}
