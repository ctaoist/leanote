package handler

import (
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"

	"leanote/internal/models"
	"leanote/internal/oid"
	"leanote/internal/types"
	"leanote/internal/web"
)

// DefaultAlbumID matches the legacy default album id (images uploaded without an
// album land here and show under the frontend's "全部图片").
const DefaultAlbumID = "52d3e8ac99c37b7f0d000001"

func isImageExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".gif", ".jpg", ".jpeg", ".png", ".bmp", ".webp":
		return true
	default:
		return false
	}
}

func readUpload(c *fiber.Ctx) ([]byte, string, error) {
	fh, err := c.FormFile("file")
	if err != nil {
		return nil, "", err
	}
	f, err := fh.Open()
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	return data, fh.Filename, err
}

// uploadImage saves an uploaded image and creates its File document.
// from == "pasteImage" treats an extension-less paste as .png.
func (h *Handler) uploadImage(c *fiber.Ctx, from, albumId string) types.Re {
	uid := web.UserOID(c)
	data, filename, err := readUpload(c)
	if err != nil || len(data) == 0 {
		return types.ErrRe("没有文件")
	}
	if h.overSize(c.Context(), cfgUploadImageSize, int64(len(data))) {
		return types.ErrRe("图片超过大小限制")
	}
	ext := strings.ToLower(filepath.Ext(filename))
	if from == "pasteImage" && ext == "" {
		ext = ".png"
	}
	if !isImageExt(ext) {
		return types.ErrRe("请上传图片")
	}
	relPath, name, size, err := h.Store.SaveImage(uid.Hex(), ext, data)
	if err != nil {
		return types.ErrRe("保存失败")
	}
	file := models.File{
		FileId:      oid.New(),
		UserId:      uid,
		Name:        name,
		Title:       filename,
		Path:        relPath,
		Size:        size,
		Type:        "",
		CreatedTime: time.Now(),
	}
	if albumOID, ok := oid.Parse(albumId); ok {
		file.AlbumId = albumOID
	} else {
		file.IsDefaultAlbum = true
		file.AlbumId, _ = oid.FromHex(DefaultAlbumID)
	}
	if _, err := h.DB.Files.InsertOne(c.Context(), file); err != nil {
		return types.ErrRe("保存失败")
	}
	item := file
	item.Path = "" // do not leak the on-disk path
	return types.Re{Ok: true, Code: 1, Msg: "Upload Success!", Id: file.FileId.Hex(), Item: item}
}

// PasteImage handles editor paste/drag uploads.
func (h *Handler) PasteImage(c *fiber.Ctx) error {
	return c.JSON(h.uploadImage(c, "pasteImage", ""))
}

// UploadImageLeaui handles album/file-picker uploads.
func (h *Handler) UploadImageLeaui(c *fiber.Ctx) error {
	return c.JSON(h.uploadImage(c, "", c.FormValue("albumId")))
}

// GetImages returns a page of the user's images, filtered by album (default
// album when none) and an optional title key. Page size is the user's configured
// imagePageSize, overridable per-request via the pageSize query (clamped 1..100).
func (h *Handler) GetImages(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	page, _ := strconv.Atoi(c.Query("page", "1"))
	if page < 1 {
		page = 1
	}
	u, _ := h.loadUser(c)
	pageSize := userImagePageSize(u)
	if v, err := strconv.Atoi(c.Query("pageSize")); err == nil && v > 0 {
		if v > 100 {
			v = 100
		}
		pageSize = v
	}
	q := bson.M{"UserId": uid, "Type": ""}
	if albumOID, ok := oid.Parse(c.Query("albumId")); ok {
		q["AlbumId"] = albumOID
	} else {
		q["IsDefaultAlbum"] = true
	}
	if key := strings.TrimSpace(c.Query("key")); key != "" {
		q["Title"] = primitive.Regex{Pattern: regexp.QuoteMeta(key), Options: "i"}
	}
	count, _ := h.DB.Files.CountDocuments(c.Context(), q)

	files := []models.File{}
	opt := options.Find().
		SetSort(bson.D{{Key: "CreatedTime", Value: -1}}).
		SetSkip(int64((page - 1) * pageSize)).
		SetLimit(int64(pageSize))
	if cur, err := h.DB.Files.Find(c.Context(), q, opt); err == nil {
		_ = cur.All(c.Context(), &files)
	}
	if files == nil {
		files = []models.File{}
	}
	return c.JSON(types.NewPage(page, pageSize, int(count), files))
}

// UpdateImageTitle renames an image. Returns bool.
func (h *Handler) UpdateImageTitle(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	fileID, ok := oid.Parse(c.FormValue("fileId"))
	if !ok {
		return c.JSON(false)
	}
	res, err := h.DB.Files.UpdateOne(c.Context(),
		bson.M{"_id": fileID, "UserId": uid},
		bson.M{"$set": bson.M{"Title": c.FormValue("title")}})
	if err != nil || res.MatchedCount == 0 {
		return c.JSON(false)
	}
	return c.JSON(true)
}

// DeleteImage removes an image document and its file on disk.
func (h *Handler) DeleteImage(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	fileID, ok := oid.Parse(c.FormValue("fileId"))
	if !ok {
		return c.JSON(types.ErrRe("参数错误"))
	}
	var file models.File
	if err := h.DB.Files.FindOne(c.Context(), bson.M{"_id": fileID, "UserId": uid}).Decode(&file); err != nil {
		return c.JSON(types.ErrRe("图片不存在"))
	}
	if _, err := h.DB.Files.DeleteOne(c.Context(), bson.M{"_id": fileID, "UserId": uid}); err != nil {
		return c.JSON(types.ErrRe("删除失败"))
	}
	h.Store.Remove(file.Path)
	return c.JSON(types.OkRe())
}

// OutputImage streams an image owned by the current user.
func (h *Handler) OutputImage(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	fileID, ok := oid.Parse(c.Query("fileId"))
	if !ok {
		return c.SendStatus(fiber.StatusNotFound)
	}
	var file models.File
	if err := h.DB.Files.FindOne(c.Context(), bson.M{"_id": fileID, "UserId": uid}).Decode(&file); err != nil || file.Path == "" {
		return c.SendStatus(fiber.StatusNotFound)
	}
	abs, err := h.Store.Abs(file.Path)
	if err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}
	return c.SendFile(abs)
}

// UploadAvatar stores a new avatar and updates user.Logo. (Wired in Phase 5
// account flow; lives here as a file operation.)
func (h *Handler) UploadAvatar(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	data, filename, err := readUpload(c)
	if err != nil || len(data) == 0 {
		return c.JSON(types.ErrRe("没有文件"))
	}
	if h.overSize(c.Context(), cfgUploadAvatarSize, int64(len(data))) {
		return c.JSON(types.ErrRe("头像超过大小限制"))
	}
	ext := strings.ToLower(filepath.Ext(filename))
	if !isImageExt(ext) {
		return c.JSON(types.ErrRe("请上传图片"))
	}
	relPath, err := h.Store.SaveAvatar(uid.Hex(), ext, data)
	if err != nil {
		return c.JSON(types.ErrRe("保存失败"))
	}
	if _, err := h.DB.Users.UpdateOne(c.Context(), bson.M{"_id": uid}, bson.M{"$set": bson.M{"Logo": relPath}}); err != nil {
		return c.JSON(types.ErrRe("保存失败"))
	}
	return c.JSON(types.Re{Ok: true, Code: 1, Msg: "Upload Success!", Id: relPath})
}
