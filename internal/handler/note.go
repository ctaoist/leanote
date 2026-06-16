package handler

import (
	"context"
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

// queryNotes runs a find against notes, sorted by UpdatedTime desc, always
// returning a non-nil slice.
func (h *Handler) queryNotes(ctx context.Context, filter bson.M) []models.Note {
	notes := []models.Note{}
	opt := options.Find().SetSort(bson.D{{Key: "UpdatedTime", Value: -1}}).SetLimit(2000)
	cur, err := h.DB.Notes.Find(ctx, filter, opt)
	if err != nil {
		return notes
	}
	defer cur.Close(ctx)
	if err := cur.All(ctx, &notes); err != nil || notes == nil {
		return []models.Note{}
	}
	return notes
}

func (h *Handler) getNote(ctx context.Context, noteId, userId oid.OID) (models.Note, bool) {
	var n models.Note
	if err := h.DB.Notes.FindOne(ctx, bson.M{"_id": noteId, "UserId": userId}).Decode(&n); err != nil {
		return n, false
	}
	return n, true
}

// ListNotes returns notes in a notebook (or all, when notebookId is empty).
// A notebook with sub-notebooks returns its own notes plus all descendants',
// matching the aggregated NumberNotes shown for it.
func (h *Handler) ListNotes(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	filter := bson.M{"UserId": uid, "IsTrash": false, "IsDeleted": bson.M{"$ne": true}}
	if nbID, ok := oid.Parse(c.Query("notebookId")); ok {
		filter["NotebookId"] = bson.M{"$in": h.notebookSubtreeOIDs(c.Context(), uid, nbID)}
	}
	return c.JSON(h.queryNotes(c.Context(), filter))
}

// ListTrashNotes returns the user's trashed notes.
func (h *Handler) ListTrashNotes(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	return c.JSON(h.queryNotes(c.Context(), bson.M{"UserId": uid, "IsTrash": true, "IsDeleted": bson.M{"$ne": true}}))
}

func (h *Handler) noteAndContent(ctx context.Context, noteId, userId oid.OID) (models.NoteDetail, bool) {
	note, ok := h.getNote(ctx, noteId, userId)
	if !ok {
		return models.NoteDetail{}, false
	}
	var content models.NoteContent
	_ = h.DB.NoteContents.FindOne(ctx, bson.M{"_id": noteId}).Decode(&content)
	return models.NoteDetail{Note: note, Content: content.Content, Abstract: content.Abstract}, true
}

// GetNoteAndContent returns a note merged with its content.
func (h *Handler) GetNoteAndContent(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	noteID, ok := oid.Parse(c.Query("noteId"))
	if !ok {
		return c.JSON(map[string]any{})
	}
	detail, ok := h.noteAndContent(c.Context(), noteID, uid)
	if !ok {
		return c.JSON(map[string]any{})
	}
	return c.JSON(detail)
}

// GetNoteContent returns the same merged shape (frontend reuses NoteAndContent).
func (h *Handler) GetNoteContent(c *fiber.Ctx) error {
	return h.GetNoteAndContent(c)
}

// UpdateNoteOrContent creates a note (IsNew) or partially updates one. Mirrors
// the Revel controller: only fields present in the POST body are written.
func (h *Handler) UpdateNoteOrContent(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	noteID, _ := oid.FromHex(c.FormValue("NoteId"))

	// ---- create ----
	if b, _ := strconvBool(c.FormValue("IsNew")); b {
		if noteID.IsZero() {
			noteID = oid.New()
		}
		nbID, _ := oid.FromHex(c.FormValue("NotebookId"))
		now := time.Now()
		isBlog := h.notebookIsBlog(c.Context(), nbID, uid)
		note := models.Note{
			NoteId:        noteID,
			UserId:        uid,
			NotebookId:    nbID,
			Title:         c.FormValue("Title"),
			Desc:          c.FormValue("Desc"),
			Src:           c.FormValue("Src"),
			ImgSrc:        c.FormValue("ImgSrc"),
			Tags:          cleanTags(strings.Split(c.FormValue("Tags"), ",")),
			IsMarkdown:    formBool(c, "IsMarkdown"),
			IsBlog:        isBlog,
			IsTrash:       false,
			UpdatedUserId: uid,
			CreatedTime:   now,
			UpdatedTime:   now,
			PublicTime:    now,
			Usn:           h.incrUsn(c.Context(), uid),
		}
		if _, err := h.DB.Notes.InsertOne(c.Context(), note); err != nil {
			return c.JSON(types.ErrRe("创建失败"))
		}
		_, _ = h.DB.NoteContents.InsertOne(c.Context(), models.NoteContent{
			NoteId:        noteID,
			UserId:        uid,
			IsBlog:        isBlog,
			Content:       c.FormValue("Content"),
			Abstract:      c.FormValue("Abstract"),
			CreatedTime:   now,
			UpdatedTime:   now,
			UpdatedUserId: uid,
		})
		h.addTags(c.Context(), uid, note.Tags)
		return c.JSON(note)
	}

	if noteID.IsZero() {
		return c.JSON(false)
	}

	// ---- partial update of note fields ----
	set := bson.M{}
	if web.Has(c, "Title") {
		set["Title"] = c.FormValue("Title")
	}
	if web.Has(c, "Desc") {
		set["Desc"] = c.FormValue("Desc")
	}
	if web.Has(c, "ImgSrc") {
		set["ImgSrc"] = c.FormValue("ImgSrc")
	}
	if web.Has(c, "Tags") {
		tags := cleanTags(strings.Split(c.FormValue("Tags"), ","))
		set["Tags"] = tags
		h.addTags(c.Context(), uid, tags)
	}
	updatedNote := false
	if len(set) > 0 {
		set["UpdatedTime"] = time.Now()
		set["UpdatedUserId"] = uid
		set["Usn"] = h.incrUsn(c.Context(), uid)
		_, _ = h.DB.Notes.UpdateOne(c.Context(), bson.M{"_id": noteID, "UserId": uid}, bson.M{"$set": set})
		updatedNote = true
	}

	// ---- content update ----
	if web.Has(c, "Content") {
		content := c.FormValue("Content")
		abstract := c.FormValue("Abstract")
		now := time.Now()
		_, _ = h.DB.NoteContents.UpdateOne(c.Context(),
			bson.M{"_id": noteID},
			bson.M{"$set": bson.M{
				"Content":       content,
				"Abstract":      abstract,
				"UpdatedTime":   now,
				"UpdatedUserId": uid,
			}})
		// Keep the note's UpdatedTime fresh and bump Usn if it wasn't already.
		noteSet := bson.M{"UpdatedTime": now}
		if !updatedNote {
			noteSet["Usn"] = h.incrUsn(c.Context(), uid)
		}
		_, _ = h.DB.Notes.UpdateOne(c.Context(), bson.M{"_id": noteID, "UserId": uid}, bson.M{"$set": noteSet})
		h.addHistory(c.Context(), noteID, uid, uid, content)
	}

	return c.JSON(true)
}

// DeleteNote moves notes to trash (soft delete).
func (h *Handler) DeleteNote(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	for _, id := range web.FormArray(c, "noteIds") {
		if noteID, ok := oid.Parse(id); ok {
			_, _ = h.DB.Notes.UpdateOne(c.Context(),
				bson.M{"_id": noteID, "UserId": uid},
				bson.M{"$set": bson.M{"IsTrash": true, "Usn": h.incrUsn(c.Context(), uid)}})
		}
	}
	return c.JSON(true)
}

// RestoreNote moves notes out of the trash (IsTrash=false).
func (h *Handler) RestoreNote(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	for _, id := range web.FormArray(c, "noteIds") {
		if noteID, ok := oid.Parse(id); ok {
			_, _ = h.DB.Notes.UpdateOne(c.Context(),
				bson.M{"_id": noteID, "UserId": uid},
				bson.M{"$set": bson.M{"IsTrash": false, "Usn": h.incrUsn(c.Context(), uid)}})
		}
	}
	return c.JSON(true)
}

// DeleteTrash permanently removes trashed notes plus their content and history.
// Only notes currently in the trash are purged (safety guard against deleting a
// live note).
func (h *Handler) DeleteTrash(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	for _, id := range web.FormArray(c, "noteIds") {
		noteID, ok := oid.Parse(id)
		if !ok {
			continue
		}
		res, err := h.DB.Notes.DeleteOne(c.Context(),
			bson.M{"_id": noteID, "UserId": uid, "IsTrash": true})
		if err != nil || res.DeletedCount == 0 {
			continue // not found or not in trash — skip
		}
		_, _ = h.DB.NoteContents.DeleteOne(c.Context(), bson.M{"_id": noteID})
		_, _ = h.DB.NoteContentHistories.DeleteOne(c.Context(), bson.M{"_id": noteID})
	}
	return c.JSON(true)
}

// MoveNote moves notes to another notebook.
func (h *Handler) MoveNote(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	nbID, ok := oid.Parse(c.FormValue("notebookId"))
	if !ok {
		return c.JSON(false)
	}
	for _, id := range web.FormArray(c, "noteIds") {
		if noteID, ok := oid.Parse(id); ok {
			_, _ = h.DB.Notes.UpdateOne(c.Context(),
				bson.M{"_id": noteID, "UserId": uid},
				bson.M{"$set": bson.M{"NotebookId": nbID, "UpdatedTime": time.Now(), "Usn": h.incrUsn(c.Context(), uid)}})
		}
	}
	return c.JSON(true)
}

// CopyNote duplicates notes into a target notebook, returning the copies.
func (h *Handler) CopyNote(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	nbID, ok := oid.Parse(c.FormValue("notebookId"))
	if !ok {
		return c.JSON(types.ErrRe("参数错误"))
	}
	copies := []models.Note{}
	for _, id := range web.FormArray(c, "noteIds") {
		srcID, ok := oid.Parse(id)
		if !ok {
			continue
		}
		src, ok := h.getNote(c.Context(), srcID, uid)
		if !ok {
			continue
		}
		var srcContent models.NoteContent
		_ = h.DB.NoteContents.FindOne(c.Context(), bson.M{"_id": srcID}).Decode(&srcContent)

		now := time.Now()
		newID := oid.New()
		dup := src
		dup.NoteId = newID
		dup.NotebookId = nbID
		dup.IsTrash = false
		dup.IsBlog = false
		dup.UpdatedUserId = uid
		dup.CreatedTime = now
		dup.UpdatedTime = now
		dup.PublicTime = now
		dup.Usn = h.incrUsn(c.Context(), uid)
		if _, err := h.DB.Notes.InsertOne(c.Context(), dup); err != nil {
			continue
		}
		_, _ = h.DB.NoteContents.InsertOne(c.Context(), models.NoteContent{
			NoteId:        newID,
			UserId:        uid,
			Content:       srcContent.Content,
			Abstract:      srcContent.Abstract,
			CreatedTime:   now,
			UpdatedTime:   now,
			UpdatedUserId: uid,
		})
		copies = append(copies, dup)
	}
	return c.JSON(types.Re{Ok: true, Item: copies})
}

// SearchNote does a case-insensitive search over Title/Desc and note content.
func (h *Handler) SearchNote(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	key := strings.TrimSpace(c.FormValue("key"))
	if key == "" {
		return c.JSON([]models.Note{})
	}
	rx := primitive.Regex{Pattern: regexp.QuoteMeta(key), Options: "i"}

	// Match note ids whose content matches.
	contentIDs := map[string]oid.OID{}
	if cur, err := h.DB.NoteContents.Find(c.Context(),
		bson.M{"UserId": uid, "Content": rx},
		options.Find().SetProjection(bson.M{"_id": 1}).SetLimit(500)); err == nil {
		var rows []struct {
			ID oid.OID `bson:"_id"`
		}
		_ = cur.All(c.Context(), &rows)
		for _, r := range rows {
			contentIDs[r.ID.Hex()] = r.ID
		}
	}

	idList := make([]oid.OID, 0, len(contentIDs))
	for _, v := range contentIDs {
		idList = append(idList, v)
	}

	or := []bson.M{{"Title": rx}, {"Desc": rx}}
	if len(idList) > 0 {
		or = append(or, bson.M{"_id": bson.M{"$in": idList}})
	}
	filter := bson.M{"UserId": uid, "IsTrash": false, "IsDeleted": bson.M{"$ne": true}, "$or": or}
	return c.JSON(h.queryNotes(c.Context(), filter))
}

// SearchNoteByTags returns notes containing all of the given tags.
func (h *Handler) SearchNoteByTags(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	tags := cleanTags(web.FormArray(c, "tags"))
	if len(tags) == 0 {
		return c.JSON([]models.Note{})
	}
	filter := bson.M{
		"UserId":    uid,
		"IsTrash":   false,
		"IsDeleted": bson.M{"$ne": true},
		"Tags":      bson.M{"$all": tags},
	}
	return c.JSON(h.queryNotes(c.Context(), filter))
}

// SetNote2Blog toggles blog/top flags on notes.
func (h *Handler) SetNote2Blog(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	isBlog := formBool(c, "isBlog")
	isTop := formBool(c, "isTop")
	now := time.Now()
	for _, id := range web.FormArray(c, "noteIds") {
		if noteID, ok := oid.Parse(id); ok {
			set := bson.M{"IsBlog": isBlog, "IsTop": isTop, "Usn": h.incrUsn(c.Context(), uid)}
			if isBlog {
				set["PublicTime"] = now
			}
			_, _ = h.DB.Notes.UpdateOne(c.Context(), bson.M{"_id": noteID, "UserId": uid}, bson.M{"$set": set})
		}
	}
	return c.JSON(true)
}

// UpdateBlogMeta edits one blog post's public metadata: custom URL title
// (de-duplicated per user), excerpt (Desc + content Abstract), and cover image.
// Partial: only submitted fields change. Returns the normalized UrlTitle.
func (h *Handler) UpdateBlogMeta(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	noteID, ok := oid.Parse(c.FormValue("noteId"))
	if !ok {
		return c.JSON(types.ErrRe("笔记不存在"))
	}
	if _, found := h.getNote(c.Context(), noteID, uid); !found {
		return c.JSON(types.ErrRe("笔记不存在"))
	}
	set := bson.M{}
	urlTitle := ""
	if web.Has(c, "UrlTitle") {
		urlTitle = h.uniqueBlogUrlTitle(c.Context(), uid, noteID, c.FormValue("UrlTitle"))
		set["UrlTitle"] = urlTitle
	}
	if web.Has(c, "Desc") {
		set["Desc"] = strings.TrimSpace(c.FormValue("Desc"))
	}
	if web.Has(c, "ImgSrc") {
		set["ImgSrc"] = strings.TrimSpace(c.FormValue("ImgSrc"))
	}
	if len(set) > 0 {
		set["Usn"] = h.incrUsn(c.Context(), uid)
		if _, err := h.DB.Notes.UpdateOne(c.Context(), bson.M{"_id": noteID, "UserId": uid}, bson.M{"$set": set}); err != nil {
			return c.JSON(types.ErrRe("保存失败"))
		}
	}
	// Mirror the excerpt into note_contents.Abstract so post cards/excerpts match.
	if web.Has(c, "Desc") {
		_, _ = h.DB.NoteContents.UpdateOne(c.Context(), bson.M{"_id": noteID, "UserId": uid},
			bson.M{"$set": bson.M{"Abstract": strings.TrimSpace(c.FormValue("Desc"))}})
	}
	return c.JSON(types.OkItem(fiber.Map{"UrlTitle": urlTitle}))
}

// uniqueBlogUrlTitle sanitizes a desired url title and ensures it's unique among
// the user's notes (auto-suffixing -2, -3, ...). Empty stays empty.
func (h *Handler) uniqueBlogUrlTitle(ctx context.Context, uid, noteID oid.OID, want string) string {
	want = sanitizeUrlTitle(want)
	if want == "" {
		return ""
	}
	cand := want
	for i := 2; i <= 100; i++ {
		n, _ := h.DB.Notes.CountDocuments(ctx, bson.M{"UserId": uid, "UrlTitle": cand, "_id": bson.M{"$ne": noteID}})
		if n == 0 {
			return cand
		}
		cand = want + "-" + strconv.Itoa(i)
	}
	return cand
}

// sanitizeUrlTitle trims, turns whitespace into '-', and strips characters that
// break a URL path segment (/ \ ? # ..). Unicode is preserved.
func sanitizeUrlTitle(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "..", "")
	s = strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', '?', '#':
			return -1
		case ' ', '\t', '\n':
			return '-'
		}
		return r
	}, s)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return strings.Trim(s, "-")
}

func (h *Handler) notebookIsBlog(ctx context.Context, notebookId, userId oid.OID) bool {
	if notebookId.IsZero() {
		return false
	}
	var nb models.Notebook
	if err := h.DB.Notebooks.FindOne(ctx, bson.M{"_id": notebookId, "UserId": userId}).Decode(&nb); err != nil {
		return false
	}
	return nb.IsBlog
}

// ----- small form helpers -----

func formBool(c *fiber.Ctx, name string) bool {
	b, _ := strconvBool(c.FormValue(name))
	return b
}

func strconvBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "on", "yes":
		return true, nil
	default:
		return false, nil
	}
}
