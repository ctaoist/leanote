package handler

import (
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"

	"leanote/internal/models"
	"leanote/internal/oid"
	"leanote/internal/web"
)

// ListHistories returns a note's content-history entries (most recent first).
func (h *Handler) ListHistories(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	noteID, ok := oid.Parse(c.Query("noteId"))
	if !ok {
		return c.JSON([]models.EachHistory{})
	}
	var hist models.NoteContentHistory
	if err := h.DB.NoteContentHistories.FindOne(c.Context(),
		bson.M{"_id": noteID, "UserId": uid}).Decode(&hist); err != nil {
		return c.JSON([]models.EachHistory{})
	}
	if hist.Histories == nil {
		return c.JSON([]models.EachHistory{})
	}
	return c.JSON(hist.Histories)
}
