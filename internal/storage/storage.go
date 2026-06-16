// Package storage handles on-disk reads/writes for images, attachments, and
// avatars under the configured file root (the live leanote install dir, so
// existing files remain reachable and new files land beside them).
package storage

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Store struct {
	Root string
}

func New(root string) *Store { return &Store{Root: root} }

func guid() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// rel paths always use forward slashes (they are stored in Mongo and resolved
// the same way the legacy app resolved them).
func rel(parts ...string) string { return strings.Join(parts, "/") }

func (s *Store) write(relPath string, data []byte) error {
	abs := filepath.Join(s.Root, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	return os.WriteFile(abs, data, 0o644)
}

// SaveImage stores an image and returns its relative path, stored name and size.
func (s *Store) SaveImage(userIdHex, ext string, data []byte) (relPath, name string, size int64, err error) {
	name = guid() + ext
	relPath = rel("files", userIdHex, "images", name)
	if err = s.write(relPath, data); err != nil {
		return "", "", 0, err
	}
	return relPath, name, int64(len(data)), nil
}

// SaveAttach stores an attachment and returns its relative path, name and size.
func (s *Store) SaveAttach(userIdHex, ext string, data []byte) (relPath, name string, size int64, err error) {
	name = guid() + ext
	relPath = rel("files", userIdHex, "attachs", name)
	if err = s.write(relPath, data); err != nil {
		return "", "", 0, err
	}
	return relPath, name, int64(len(data)), nil
}

// SaveAvatar stores an avatar under public/upload/<user>/logo and returns its
// relative path (the value persisted as user.Logo; the frontend maps
// "public/upload/..." → "/public/upload/...").
func (s *Store) SaveAvatar(userIdHex, ext string, data []byte) (relPath string, err error) {
	name := guid() + ext
	relPath = rel("public", "upload", userIdHex, "logo", name)
	if err = s.write(relPath, data); err != nil {
		return "", err
	}
	return relPath, nil
}

// Abs resolves a stored relative path to an absolute path, guarding against
// path traversal outside the root.
func (s *Store) Abs(relPath string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash("/" + strings.TrimLeft(relPath, "/")))
	abs := filepath.Join(s.Root, clean)
	rootAbs, _ := filepath.Abs(s.Root)
	if !strings.HasPrefix(abs, rootAbs) {
		return "", errors.New("invalid path")
	}
	return abs, nil
}

// Remove deletes a stored file (best-effort). Legacy avatar paths beginning
// with "upload" actually live under public/, matching the old delete logic.
func (s *Store) Remove(relPath string) {
	p := strings.TrimLeft(relPath, "/")
	if strings.HasPrefix(p, "upload") {
		p = "public/" + p
	}
	if abs, err := s.Abs(p); err == nil {
		_ = os.Remove(abs)
	}
}

// ----- blog themes (file-based theme directories under public/upload) -----

// Digest3 buckets an id the way legacy leanote did (sum of runes mod 1000), used
// to spread theme dirs across public/upload/<digest3>/<userId>/themes/<themeId>.
func Digest3(s string) string {
	var b rune
	for _, k := range s {
		b += k
	}
	return strconv.Itoa(int(b % 1000))
}

// MakeThemeDir creates a fresh theme directory and returns its root-relative
// path (the value persisted as theme.Path).
func (s *Store) MakeThemeDir(userIdHex, themeIdHex string) (string, error) {
	relPath := rel("public", "upload", Digest3(userIdHex), userIdHex, "themes", themeIdHex)
	abs, err := s.Abs(relPath)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return "", err
	}
	return relPath, nil
}

// ThemeDirAbs resolves a theme's root-relative path to an absolute directory,
// requiring it to live under public/upload so theme file ops can never reach
// arbitrary locations.
func (s *Store) ThemeDirAbs(themeRel string) (string, error) {
	t := strings.TrimLeft(filepath.ToSlash(themeRel), "/")
	if !strings.HasPrefix(t, "public/upload/") || strings.Contains(t, "..") {
		return "", errors.New("invalid theme path")
	}
	return s.Abs(themeRel)
}

// safeThemeFile resolves filename within a theme directory, rejecting traversal.
func (s *Store) safeThemeFile(themeRel, filename string) (string, error) {
	if filename == "" || strings.Contains(filename, "..") {
		return "", errors.New("invalid filename")
	}
	base, err := s.ThemeDirAbs(themeRel)
	if err != nil {
		return "", err
	}
	target := filepath.Join(base, filepath.FromSlash(filename))
	if target != base && !strings.HasPrefix(target, base+string(os.PathSeparator)) {
		return "", errors.New("invalid filename")
	}
	return target, nil
}

// ReadThemeFile reads one file from a theme directory.
func (s *Store) ReadThemeFile(themeRel, filename string) ([]byte, error) {
	p, err := s.safeThemeFile(themeRel, filename)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

// WriteThemeFile writes one file into a theme directory (creating parent dirs).
func (s *Store) WriteThemeFile(themeRel, filename string, data []byte) error {
	p, err := s.safeThemeFile(themeRel, filename)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}

// RemoveThemeFile deletes one file from a theme directory.
func (s *Store) RemoveThemeFile(themeRel, filename string) error {
	p, err := s.safeThemeFile(themeRel, filename)
	if err != nil {
		return err
	}
	return os.Remove(p)
}

// ListThemeFiles returns the theme's files as theme-relative forward-slash paths,
// skipping directories and any .git folder.
func (s *Store) ListThemeFiles(themeRel string) ([]string, error) {
	base, err := s.ThemeDirAbs(themeRel)
	if err != nil {
		return nil, err
	}
	out := []string{}
	err = filepath.WalkDir(base, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		r, relErr := filepath.Rel(base, p)
		if relErr != nil {
			return relErr
		}
		out = append(out, filepath.ToSlash(r))
		return nil
	})
	sort.Strings(out)
	return out, err
}

// RemoveThemeDir deletes a whole theme directory.
func (s *Store) RemoveThemeDir(themeRel string) error {
	base, err := s.ThemeDirAbs(themeRel)
	if err != nil {
		return err
	}
	return os.RemoveAll(base)
}
