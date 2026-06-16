package blog

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// themeCache memoizes parsed theme template sets, keyed by absolute theme dir.
// An entry is invalidated when any *.html file's mtime advances, so editing a
// theme file (via the theme editor) is picked up without a server restart.
type themeEntry struct {
	tpl   *template.Template
	stamp int64 // newest *.html mtime (unix nanos)
}

var themeCache sync.Map // absDir -> *themeEntry

// LoadTheme parses every *.html file in absDir into a single template set keyed
// by base filename, so {{template "header.html" .}} resolves across files
// (mirrors app/lea/blog/Template.go). The result is cached by dir + mtime.
func LoadTheme(absDir string) (*template.Template, error) {
	entries, err := os.ReadDir(absDir)
	if err != nil {
		return nil, err
	}
	var stamp int64
	htmlFiles := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".html") {
			continue
		}
		htmlFiles = append(htmlFiles, e.Name())
		if info, ierr := e.Info(); ierr == nil {
			if m := info.ModTime().UnixNano(); m > stamp {
				stamp = m
			}
		}
	}
	if cached, ok := themeCache.Load(absDir); ok {
		if ce := cached.(*themeEntry); ce.stamp == stamp {
			return ce.tpl, nil
		}
	}

	root := template.New("blog").Funcs(FuncMap())
	for _, name := range htmlFiles {
		data, rerr := os.ReadFile(filepath.Join(absDir, name))
		if rerr != nil {
			continue
		}
		// Parse each file under its base name. A single bad file is skipped (a
		// theme may ship partials it never includes); the rest stay usable.
		if _, perr := root.New(name).Parse(string(data)); perr != nil {
			continue
		}
	}
	themeCache.Store(absDir, &themeEntry{tpl: root, stamp: stamp})
	return root, nil
}
