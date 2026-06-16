package main

import (
	"embed"
	"io/fs"
)

// webDist holds the built SPA so the single Go binary serves the frontend too.
// The frontend (web-src) builds into web-src/dist via `cd web-src && npm run
// build` (vite build.outDir = "dist"); then `go build` at the repo root bakes it
// into the binary.
//
// The embed directive lives here, in the root package main, rather than in a
// dedicated package: go:embed patterns cannot contain "..", so the embedding
// file must sit at the module root for web-src/dist to be a reachable
// subdirectory.
//
// Build order matters: run the frontend build BEFORE `go build`, otherwise the
// embedded tree only contains the placeholder index.html committed under
// web-src/dist.
//
//go:embed all:web-src/dist
var webDist embed.FS

// webuiFS returns the embedded SPA tree rooted at web-src/dist, so "index.html"
// and "assets/..." sit at the root.
func webuiFS() fs.FS {
	sub, err := fs.Sub(webDist, "web-src/dist")
	if err != nil {
		panic(err) // dist is embedded at build time; this cannot fail
	}
	return sub
}
