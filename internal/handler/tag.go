package handler

import (
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"

	"leanote/internal/models"
	"leanote/internal/types"
	"leanote/internal/web"
)

// DeleteTag removes a tag from the user's tag list and from every note.
func (h *Handler) DeleteTag(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	tag := c.FormValue("tag")
	if tag == "" {
		return c.JSON(types.OkRe())
	}
	_, _ = h.DB.Tags.UpdateOne(c.Context(), bson.M{"_id": uid}, bson.M{"$pull": bson.M{"Tags": tag}})
	_, _ = h.DB.Notes.UpdateMany(c.Context(),
		bson.M{"UserId": uid, "Tags": tag},
		bson.M{"$pull": bson.M{"Tags": tag}})
	return c.JSON(types.OkRe())
}

// UpdateTag renames a tag when a target is supplied; the current frontend sends
// only `tag`, in which case this is a no-op success.
func (h *Handler) UpdateTag(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	tag := c.FormValue("tag")
	newTag := c.FormValue("targetTag")
	if newTag == "" {
		newTag = c.FormValue("newTag")
	}
	if tag == "" || newTag == "" || tag == newTag {
		return c.JSON(types.OkRe())
	}
	_, _ = h.DB.Tags.UpdateOne(c.Context(), bson.M{"_id": uid}, bson.M{"$pull": bson.M{"Tags": tag}})
	h.addTags(c.Context(), uid, []string{newTag})

	// Rename across notes (user-scoped, modest volume): rewrite each Tags slice.
	cur, err := h.DB.Notes.Find(c.Context(), bson.M{"UserId": uid, "Tags": tag})
	if err == nil {
		defer cur.Close(c.Context())
		var notes []models.Note
		if cur.All(c.Context(), &notes) == nil {
			for _, n := range notes {
				renamed := make([]string, 0, len(n.Tags))
				for _, t := range n.Tags {
					if t == tag {
						t = newTag
					}
					renamed = append(renamed, t)
				}
				_, _ = h.DB.Notes.UpdateOne(c.Context(),
					bson.M{"_id": n.NoteId, "UserId": uid},
					bson.M{"$set": bson.M{"Tags": cleanTags(renamed)}})
			}
		}
	}
	return c.JSON(types.OkRe())
}
