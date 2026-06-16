package handler

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"leanote/internal/models"
	"leanote/internal/oid"
	"leanote/internal/types"
	"leanote/internal/web"
)

// notebookNoteCounts returns notebookHex -> live note count (non-trash, non-deleted).
func (h *Handler) notebookNoteCounts(ctx context.Context, userId oid.OID) map[string]int {
	counts := map[string]int{}
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"UserId": userId, "IsTrash": bson.M{"$ne": true}, "IsDeleted": bson.M{"$ne": true}}}},
		{{Key: "$group", Value: bson.M{"_id": "$NotebookId", "c": bson.M{"$sum": 1}}}},
	}
	cur, err := h.DB.Notes.Aggregate(ctx, pipeline)
	if err != nil {
		return counts
	}
	defer cur.Close(ctx)
	var rows []struct {
		ID oid.OID `bson:"_id"`
		C  int     `bson:"c"`
	}
	if err := cur.All(ctx, &rows); err != nil {
		return counts
	}
	for _, r := range rows {
		counts[r.ID.Hex()] = r.C
	}
	return counts
}

// GetNotebooks returns the user's notebooks as a flat list (each carrying
// ParentNotebookId). The frontend flattens Subs then rebuilds the tree by
// ParentNotebookId, so a flat list is sufficient.
func (h *Handler) GetNotebooks(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	notebooks := h.userNotebooks(c.Context(), uid)
	// NumberNotes aggregates the notebook's own notes plus all descendants', so it
	// matches what ListNotes returns when that notebook is selected.
	own := h.notebookNoteCounts(c.Context(), uid)
	children := childrenMap(notebooks)
	for i := range notebooks {
		total := 0
		for _, hx := range subtreeHexes(notebooks[i].NotebookId.Hex(), children) {
			total += own[hx]
		}
		notebooks[i].NumberNotes = total
	}
	return c.JSON(notebooks)
}

// userNotebooks loads a user's live (non-deleted) notebooks.
func (h *Handler) userNotebooks(ctx context.Context, uid oid.OID) []models.Notebook {
	notebooks := []models.Notebook{}
	if cur, err := h.DB.Notebooks.Find(ctx, bson.M{"UserId": uid, "IsDeleted": bson.M{"$ne": true}}); err == nil {
		defer cur.Close(ctx)
		_ = cur.All(ctx, &notebooks)
	}
	if notebooks == nil {
		notebooks = []models.Notebook{}
	}
	return notebooks
}

// childrenMap inverts ParentNotebookId into parentHex -> []childHex. The child's
// parent link is the authoritative tree edge (the parent's stored
// ChildNotebookIds can be stale).
func childrenMap(notebooks []models.Notebook) map[string][]string {
	m := map[string][]string{}
	for _, nb := range notebooks {
		if !nb.ParentNotebookId.IsZero() {
			pid := nb.ParentNotebookId.Hex()
			m[pid] = append(m[pid], nb.NotebookId.Hex())
		}
	}
	return m
}

// subtreeHexes returns rootHex plus every descendant notebook id hex (DFS,
// cycle-safe). With no children it returns just [rootHex].
func subtreeHexes(rootHex string, children map[string][]string) []string {
	out := []string{}
	seen := map[string]bool{}
	stack := []string{rootHex}
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
		stack = append(stack, children[id]...)
	}
	return out
}

// notebookSubtreeOIDs returns the notebook plus all its descendants as OIDs (for
// an $in note query). When the notebook has no children this is just [root], so
// callers transparently degrade to an exact-notebook query.
func (h *Handler) notebookSubtreeOIDs(ctx context.Context, uid, root oid.OID) []oid.OID {
	children := childrenMap(h.userNotebooks(ctx, uid))
	hexes := subtreeHexes(root.Hex(), children)
	ids := make([]oid.OID, 0, len(hexes))
	for _, hx := range hexes {
		if o, ok := oid.Parse(hx); ok {
			ids = append(ids, o)
		}
	}
	return ids
}

// AddNotebook creates a notebook. Returns the new Notebook, or false on error.
func (h *Handler) AddNotebook(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	title := c.FormValue("title")
	nbID, _ := oid.FromHex(c.FormValue("notebookId"))
	if nbID.IsZero() {
		nbID = oid.New()
	}
	parentID, _ := oid.FromHex(c.FormValue("parentNotebookId"))

	seq, _ := h.DB.Notebooks.CountDocuments(c.Context(), bson.M{"UserId": uid})
	now := time.Now()
	nb := models.Notebook{
		NotebookId:       nbID,
		UserId:           uid,
		ParentNotebookId: parentID,
		Title:            title,
		UrlTitle:         h.uniqueNotebookUrlTitle(c.Context(), uid, nbID, title),
		Seq:              int(seq),
		CreatedTime:      now,
		UpdatedTime:      now,
		Usn:              h.incrUsn(c.Context(), uid),
	}
	if _, err := h.DB.Notebooks.InsertOne(c.Context(), nb); err != nil {
		return c.JSON(false)
	}
	return c.JSON(nb)
}

// uniqueNotebookUrlTitle derives a URL-safe, per-user-unique slug for a notebook
// from its title (reusing sanitizeUrlTitle), falling back to the notebook id when
// the title sanitizes to empty. Mirrors leanote's GetUrTitle; keeps cate links
// readable and resolvable by blog.resolveCate.
func (h *Handler) uniqueNotebookUrlTitle(ctx context.Context, uid, notebookID oid.OID, title string) string {
	want := sanitizeUrlTitle(title)
	if want == "" {
		want = notebookID.Hex()
	}
	cand := want
	for i := 2; i <= 100; i++ {
		n, _ := h.DB.Notebooks.CountDocuments(ctx, bson.M{"UserId": uid, "UrlTitle": cand, "_id": bson.M{"$ne": notebookID}})
		if n == 0 {
			return cand
		}
		cand = want + "-" + strconv.Itoa(i)
	}
	return cand
}

// UpdateNotebookTitle renames a notebook. Returns bool.
func (h *Handler) UpdateNotebookTitle(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	nbID, ok := oid.Parse(c.FormValue("notebookId"))
	if !ok {
		return c.JSON(false)
	}
	res, err := h.DB.Notebooks.UpdateOne(c.Context(),
		bson.M{"_id": nbID, "UserId": uid},
		bson.M{"$set": bson.M{
			"Title":       c.FormValue("title"),
			"UrlTitle":    h.uniqueNotebookUrlTitle(c.Context(), uid, nbID, c.FormValue("title")),
			"UpdatedTime": time.Now(),
			"Usn":         h.incrUsn(c.Context(), uid),
		}})
	if err != nil || res.MatchedCount == 0 {
		return c.JSON(false)
	}
	return c.JSON(true)
}

// DeleteNotebook soft-deletes an EMPTY notebook (no notes, no child notebooks).
func (h *Handler) DeleteNotebook(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	nbID, ok := oid.Parse(c.Query("notebookId"))
	if !ok {
		return c.JSON(types.ErrRe("参数错误"))
	}
	noteCount, _ := h.DB.Notes.CountDocuments(c.Context(),
		bson.M{"UserId": uid, "NotebookId": nbID, "IsDeleted": bson.M{"$ne": true}})
	if noteCount > 0 {
		return c.JSON(types.ErrRe("请先清空或移走笔记本下的笔记"))
	}
	childCount, _ := h.DB.Notebooks.CountDocuments(c.Context(),
		bson.M{"UserId": uid, "ParentNotebookId": nbID, "IsDeleted": bson.M{"$ne": true}})
	if childCount > 0 {
		return c.JSON(types.ErrRe("请先删除子笔记本"))
	}
	_, err := h.DB.Notebooks.UpdateOne(c.Context(),
		bson.M{"_id": nbID, "UserId": uid},
		bson.M{"$set": bson.M{"IsDeleted": true, "Usn": h.incrUsn(c.Context(), uid)}})
	if err != nil {
		return c.JSON(types.ErrRe("删除失败"))
	}
	return c.JSON(types.OkRe())
}

// DragNotebooks reparents one notebook and reorders its siblings by Seq.
func (h *Handler) DragNotebooks(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	var payload struct {
		CurNotebookId    string   `json:"curNotebookId"`
		ParentNotebookId string   `json:"parentNotebookId"`
		Siblings         []string `json:"siblings"`
	}
	if err := json.Unmarshal([]byte(c.FormValue("data")), &payload); err != nil {
		return c.JSON(false)
	}
	curID, ok := oid.Parse(payload.CurNotebookId)
	if !ok {
		return c.JSON(false)
	}
	// Reparent (unset to make it a root notebook).
	if parentID, ok := oid.Parse(payload.ParentNotebookId); ok {
		_, _ = h.DB.Notebooks.UpdateOne(c.Context(),
			bson.M{"_id": curID, "UserId": uid},
			bson.M{"$set": bson.M{"ParentNotebookId": parentID}})
	} else {
		_, _ = h.DB.Notebooks.UpdateOne(c.Context(),
			bson.M{"_id": curID, "UserId": uid},
			bson.M{"$unset": bson.M{"ParentNotebookId": ""}})
	}
	// Reorder siblings.
	for i, sib := range payload.Siblings {
		if sibID, ok := oid.Parse(sib); ok {
			_, _ = h.DB.Notebooks.UpdateOne(c.Context(),
				bson.M{"_id": sibID, "UserId": uid},
				bson.M{"$set": bson.M{"Seq": i}})
		}
	}
	return c.JSON(true)
}
