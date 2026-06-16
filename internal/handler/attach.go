package handler

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"leanote/internal/models"
	"leanote/internal/oid"
	"leanote/internal/types"
	"leanote/internal/web"
)

// noteOwnedBy reports whether the note exists and belongs to the user.
func (h *Handler) noteOwnedBy(c *fiber.Ctx, noteID, userID oid.OID) bool {
	cnt, _ := h.DB.Notes.CountDocuments(c.Context(), bson.M{"_id": noteID, "UserId": userID})
	return cnt > 0
}

// GetAttachs returns a note's attachments as a plain array (frontend expects an
// array, not the legacy Re{List} wrapper).
func (h *Handler) GetAttachs(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	noteID, ok := oid.Parse(c.Query("noteId"))
	if !ok || !h.noteOwnedBy(c, noteID, uid) {
		return c.JSON([]models.Attach{})
	}
	attachs := []models.Attach{}
	opt := options.Find().SetSort(bson.D{{Key: "CreatedTime", Value: -1}})
	if cur, err := h.DB.Attachs.Find(c.Context(), bson.M{"NoteId": noteID}, opt); err == nil {
		_ = cur.All(c.Context(), &attachs)
	}
	if attachs == nil {
		attachs = []models.Attach{}
	}
	return c.JSON(attachs)
}

// UploadAttach stores an attachment for a note and bumps the note's AttachNum.
func (h *Handler) UploadAttach(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	noteID, ok := oid.Parse(c.FormValue("noteId"))
	if !ok || !h.noteOwnedBy(c, noteID, uid) {
		return c.JSON(types.ErrRe("笔记不存在"))
	}
	data, filename, err := readUpload(c)
	if err != nil || len(data) == 0 {
		return c.JSON(types.ErrRe("没有文件"))
	}
	if h.overSize(c.Context(), cfgUploadAttachSize, int64(len(data))) {
		return c.JSON(types.ErrRe("附件超过大小限制"))
	}
	ext := strings.ToLower(filepath.Ext(filename))
	relPath, name, size, err := h.Store.SaveAttach(uid.Hex(), ext, data)
	if err != nil {
		return c.JSON(types.ErrRe("保存失败"))
	}
	attach := models.Attach{
		AttachId:     oid.New(),
		NoteId:       noteID,
		UploadUserId: uid,
		Name:         name,
		Title:        filename,
		Size:         size,
		Type:         strings.TrimPrefix(ext, "."),
		Path:         relPath,
		CreatedTime:  time.Now(),
	}
	if _, err := h.DB.Attachs.InsertOne(c.Context(), attach); err != nil {
		return c.JSON(types.ErrRe("保存失败"))
	}
	_, _ = h.DB.Notes.UpdateOne(c.Context(), bson.M{"_id": noteID, "UserId": uid}, bson.M{"$inc": bson.M{"AttachNum": 1}})

	item := attach
	item.Path = ""
	return c.JSON(types.Re{Ok: true, Id: attach.AttachId.Hex(), Item: item})
}

// DeleteAttach removes an attachment and decrements the note's AttachNum.
func (h *Handler) DeleteAttach(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	attachID, ok := oid.Parse(c.FormValue("attachId"))
	if !ok {
		return c.JSON(types.ErrRe("参数错误"))
	}
	var attach models.Attach
	if err := h.DB.Attachs.FindOne(c.Context(), bson.M{"_id": attachID}).Decode(&attach); err != nil {
		return c.JSON(types.ErrRe("附件不存在"))
	}
	if !h.noteOwnedBy(c, attach.NoteId, uid) {
		return c.JSON(types.ErrRe("无权限"))
	}
	if _, err := h.DB.Attachs.DeleteOne(c.Context(), bson.M{"_id": attachID}); err != nil {
		return c.JSON(types.ErrRe("删除失败"))
	}
	h.Store.Remove(attach.Path)
	_, _ = h.DB.Notes.UpdateOne(c.Context(), bson.M{"_id": attach.NoteId, "UserId": uid}, bson.M{"$inc": bson.M{"AttachNum": -1}})
	return c.JSON(types.OkRe())
}

// Download streams an attachment as a file download (Content-Disposition).
func (h *Handler) Download(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	attachID, ok := oid.Parse(c.Query("attachId"))
	if !ok {
		return c.SendStatus(fiber.StatusNotFound)
	}
	var attach models.Attach
	if err := h.DB.Attachs.FindOne(c.Context(), bson.M{"_id": attachID}).Decode(&attach); err != nil || attach.Path == "" {
		return c.SendStatus(fiber.StatusNotFound)
	}
	if !h.noteOwnedBy(c, attach.NoteId, uid) {
		return c.SendStatus(fiber.StatusForbidden)
	}
	abs, err := h.Store.Abs(attach.Path)
	if err != nil {
		return c.SendStatus(fiber.StatusNotFound)
	}
	name := attach.Title
	if name == "" {
		name = attach.Name
	}
	return c.Download(abs, name)
}
