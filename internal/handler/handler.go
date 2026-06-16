// Package handler holds the Fiber HTTP handlers, grouped by domain across files.
package handler

import (
	"context"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"leanote/config"
	"leanote/internal/blog"
	"leanote/internal/db"
	"leanote/internal/models"
	"leanote/internal/oid"
	"leanote/internal/storage"
)

type Handler struct {
	Cfg   config.Config
	DB    *db.DB
	Store *storage.Store
	Blog  *blog.Renderer
}

func New(cfg config.Config, database *db.DB) *Handler {
	store := storage.New(cfg.FileRoot)
	return &Handler{Cfg: cfg, DB: database, Store: store, Blog: blog.NewRenderer(database, store, cfg)}
}

// findUserByName looks up a user by (lowercased) email or username.
func (h *Handler) findUserByName(ctx context.Context, name string) (models.User, bool) {
	var u models.User
	err := h.DB.Users.FindOne(ctx, bson.M{"$or": []bson.M{
		{"Email": name},
		{"Username": name},
	}}).Decode(&u)
	if err != nil {
		return u, false
	}
	return u, true
}

// incrUsn atomically increments the user's global update-sequence number and
// returns the new value (mirrors UserService.IncrUsn).
func (h *Handler) incrUsn(ctx context.Context, userId oid.OID) int {
	var res struct {
		Usn int `bson:"Usn"`
	}
	opt := options.FindOneAndUpdate().
		SetReturnDocument(options.After).
		SetProjection(bson.M{"Usn": 1})
	if err := h.DB.Users.FindOneAndUpdate(ctx, bson.M{"_id": userId},
		bson.M{"$inc": bson.M{"Usn": 1}}, opt).Decode(&res); err != nil {
		return 0
	}
	return res.Usn
}

func cleanTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// addTags upserts the user's tag document, adding any new tags.
func (h *Handler) addTags(ctx context.Context, userId oid.OID, tags []string) {
	clean := cleanTags(tags)
	if len(clean) == 0 {
		return
	}
	_, _ = h.DB.Tags.UpdateOne(ctx,
		bson.M{"_id": userId},
		bson.M{"$addToSet": bson.M{"Tags": bson.M{"$each": clean}}},
		options.Update().SetUpsert(true))
}

const historyMaxSize = 10

// addHistory prepends a content-history entry (most recent first), capped at
// historyMaxSize. Skips empty content (mirrors NoteContentHistoryService).
func (h *Handler) addHistory(ctx context.Context, noteId, userId, updatedUserId oid.OID, content string) {
	if content == "" {
		return
	}
	entry := models.EachHistory{UpdatedUserId: updatedUserId, UpdatedTime: time.Now(), Content: content}
	var hist models.NoteContentHistory
	err := h.DB.NoteContentHistories.FindOne(ctx, bson.M{"_id": noteId, "UserId": userId}).Decode(&hist)
	if err != nil {
		_, _ = h.DB.NoteContentHistories.InsertOne(ctx, models.NoteContentHistory{
			NoteId: noteId, UserId: userId, Histories: []models.EachHistory{entry},
		})
		return
	}
	list := append([]models.EachHistory{entry}, hist.Histories...)
	if len(list) > historyMaxSize {
		list = list[:historyMaxSize]
	}
	_, _ = h.DB.NoteContentHistories.UpdateOne(ctx,
		bson.M{"_id": noteId, "UserId": userId},
		bson.M{"$set": bson.M{"Histories": list}})
}
