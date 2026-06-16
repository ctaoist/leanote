package blog

import (
	"context"
	"path/filepath"
	"regexp"

	"go.mongodb.org/mongo-driver/bson"

	"leanote/internal/models"
	"leanote/internal/oid"
)

// outputImageRe matches a local image reference produced by the editor:
// /file/outputImage?fileId=<24-hex>. Absolute http(s) URLs (e.g. S3 image beds)
// don't match and are left untouched.
var outputImageRe = regexp.MustCompile(`/file/outputImage\?fileId=([0-9a-fA-F]{24})`)

// rewriteImages rewrites local image references in a post/single body so they
// resolve outside the authenticated app:
//   - dynamic: → /blog/image/<id> (public passthrough route)
//   - static:  → <imgBase>/assets/img/<id><ext>, and records id→ext so the
//     generator can copy the file into the output tree
//
// imgMode "" leaves content unchanged.
func (r *Renderer) rewriteImages(ctx context.Context, content string, env *renderEnv) string {
	if env.imgMode == "" || content == "" {
		return content
	}
	return outputImageRe.ReplaceAllStringFunc(content, func(m string) string {
		id := outputImageRe.FindStringSubmatch(m)[1]
		if env.imgMode == "dynamic" {
			return "/blog/image/" + id
		}
		ext := r.imageExt(ctx, id)
		if env.imgs != nil {
			env.imgs[id] = ext
		}
		return env.basePath + "/assets/img/" + id + ext
	})
}

// imageExt returns the on-disk file extension for an image fileId (defaults to
// .png when the file or its extension can't be determined).
func (r *Renderer) imageExt(ctx context.Context, idHex string) string {
	o, ok := oid.Parse(idHex)
	if !ok {
		return ".png"
	}
	var f models.File
	if err := r.DB.Files.FindOne(ctx, bson.M{"_id": o}).Decode(&f); err == nil {
		if e := filepath.Ext(f.Path); e != "" {
			return e
		}
		if e := filepath.Ext(f.Name); e != "" {
			return e
		}
	}
	return ".png"
}
