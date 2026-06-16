package handler

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"leanote/internal/models"
	"leanote/internal/oid"
	"leanote/internal/types"
	"leanote/internal/web"
)

// GetAlbums returns the user's albums (the frontend reads a plain array).
func (h *Handler) GetAlbums(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	albums := []models.Album{}
	opt := options.Find().SetSort(bson.D{{Key: "Seq", Value: 1}, {Key: "CreatedTime", Value: 1}})
	if cur, err := h.DB.Albums.Find(c.Context(), bson.M{"UserId": uid}, opt); err == nil {
		_ = cur.All(c.Context(), &albums)
	}
	if albums == nil {
		albums = []models.Album{}
	}
	return c.JSON(albums)
}

// AddAlbum creates an album, returning the album or false.
func (h *Handler) AddAlbum(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	album := models.Album{
		AlbumId:     oid.New(),
		UserId:      uid,
		Name:        c.FormValue("name"),
		Seq:         -1,
		Type:        0,
		CreatedTime: time.Now(),
	}
	if _, err := h.DB.Albums.InsertOne(c.Context(), album); err != nil {
		return c.JSON(false)
	}
	return c.JSON(album)
}

// UpdateAlbum renames an album. Returns bool.
func (h *Handler) UpdateAlbum(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	albumID, ok := oid.Parse(c.FormValue("albumId"))
	if !ok {
		return c.JSON(false)
	}
	res, err := h.DB.Albums.UpdateOne(c.Context(),
		bson.M{"_id": albumID, "UserId": uid},
		bson.M{"$set": bson.M{"Name": c.FormValue("name")}})
	if err != nil || res.MatchedCount == 0 {
		return c.JSON(false)
	}
	return c.JSON(true)
}

// DeleteAlbum deletes an empty album (no images). Returns Re.
func (h *Handler) DeleteAlbum(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	albumID, ok := oid.Parse(c.FormValue("albumId"))
	if !ok {
		return c.JSON(types.ErrRe("参数错误"))
	}
	imgCount, _ := h.DB.Files.CountDocuments(c.Context(), bson.M{"UserId": uid, "AlbumId": albumID})
	if imgCount > 0 {
		return c.JSON(types.ErrRe("请先删除或移走相册内的图片"))
	}
	if _, err := h.DB.Albums.DeleteOne(c.Context(), bson.M{"_id": albumID, "UserId": uid}); err != nil {
		return c.JSON(types.ErrRe("删除失败"))
	}
	return c.JSON(types.OkRe())
}
