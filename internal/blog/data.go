package blog

import (
	"context"
	"net/url"
	"sort"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"leanote/internal/models"
	"leanote/internal/oid"
	"leanote/internal/types"
)

// Post is the template-facing view of a blog note (mirrors leanote info.Post).
// Times stay as time.Time so {{dateFormat .CreatedTime "..."}} works.
type Post struct {
	NoteId      string
	NotebookId  string
	Title       string
	UrlTitle    string
	ImgSrc      string
	CreatedTime time.Time
	UpdatedTime time.Time
	PublicTime  time.Time
	Desc        string
	Abstract    string
	Content     string
	Tags        []string
	Cates       []CateRef
	CommentNum  int
	ReadNum     int
	LikeNum     int
	IsMarkdown  bool
	IsTop       bool
}

// CateRef is a post's category breadcrumb entry ({{range .Cates}}).
type CateRef struct {
	Title    string
	UrlTitle string
	CateId   string
}

// TagCount is one blog tag and how many posts carry it ({{range $.tags}}).
type TagCount struct {
	Tag   string
	Count int
}

// Archive groups a year's posts ({{range $.archives}} … {{range .Posts}}).
type Archive struct {
	Year  int
	Posts []*Post
}

// blogSortFieldOK whitelists sort fields (mirrors handler/blog.go blogSortFields).
var blogSortFieldOK = map[string]bool{
	"CreatedTime": true, "UpdatedTime": true, "PublicTime": true,
	"Title": true, "ReadNum": true, "LikeNum": true,
}

func safeSortField(f string) string {
	if blogSortFieldOK[f] {
		return f
	}
	return "PublicTime"
}

func sortDir(isAsc bool) int {
	if isAsc {
		return 1
	}
	return -1
}

// blogFilter is the base query for a user's live blog notes.
func blogFilter(uid oid.OID) bson.M {
	return bson.M{"UserId": uid, "IsBlog": true, "IsTrash": false, "IsDeleted": bson.M{"$ne": true}}
}

// ListBlogs returns one page of a user's blog posts (abstract only). When
// topFirst is set, pinned posts sort ahead of the chosen field (the index page).
func (r *Renderer) ListBlogs(ctx context.Context, uid, notebookId oid.OID, page, pageSize int, sortField string, isAsc, topFirst bool) (types.Page, []*Post) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}
	sortField = safeSortField(sortField)
	filter := blogFilter(uid)
	if !notebookId.IsZero() {
		filter["NotebookId"] = bson.M{"$in": r.subtreeNotebookIDs(ctx, uid, notebookId)}
	}

	count, _ := r.DB.Notes.CountDocuments(ctx, filter)
	sortD := bson.D{}
	if topFirst {
		sortD = append(sortD, bson.E{Key: "IsTop", Value: -1})
	}
	sortD = append(sortD, bson.E{Key: sortField, Value: sortDir(isAsc)})
	opt := options.Find().SetSort(sortD).SetSkip(int64((page - 1) * pageSize)).SetLimit(int64(pageSize))

	notes := r.findNotes(ctx, filter, opt)
	posts := r.notesToPosts(ctx, notes, false)
	return types.NewPage(page, pageSize, int(count), posts), posts
}

// GetBlogByIdOrUrl finds a single published post (with full Content) by note id
// or by UrlTitle. userId scopes the UrlTitle lookup.
func (r *Renderer) GetBlogByIdOrUrl(ctx context.Context, uid oid.OID, idOrUrl string) (*Post, bool) {
	var note models.Note
	if o, ok := oid.Parse(idOrUrl); ok {
		if err := r.DB.Notes.FindOne(ctx, bson.M{"_id": o, "IsBlog": true, "IsTrash": false}).Decode(&note); err == nil {
			return r.oneNoteToPost(ctx, note), true
		}
	}
	// UrlTitle lookup (try raw and URL-encoded — leanote stores encodeValue(title)).
	for _, ut := range []string{idOrUrl, url.QueryEscape(idOrUrl)} {
		q := blogFilter(uid)
		q["UrlTitle"] = ut
		if err := r.DB.Notes.FindOne(ctx, q).Decode(&note); err == nil {
			return r.oneNoteToPost(ctx, note), true
		}
	}
	// Title fallback: posts without a stored UrlTitle link by their title
	// (see fixPost), so resolve those by an exact Title match.
	if idOrUrl != "" {
		q := blogFilter(uid)
		q["Title"] = idOrUrl
		if err := r.DB.Notes.FindOne(ctx, q).Decode(&note); err == nil {
			return r.oneNoteToPost(ctx, note), true
		}
	}
	return nil, false
}

// BlogTags aggregates the tags across a user's blog posts, most-used first.
func (r *Renderer) BlogTags(ctx context.Context, uid oid.OID) []TagCount {
	opt := options.Find().SetProjection(bson.M{"Tags": 1})
	notes := r.findNotes(ctx, blogFilter(uid), opt)
	counts := map[string]int{}
	for _, n := range notes {
		for _, t := range n.Tags {
			if t = strings.TrimSpace(t); t != "" {
				counts[t]++
			}
		}
	}
	out := make([]TagCount, 0, len(counts))
	for t, c := range counts {
		out = append(out, TagCount{Tag: t, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Tag < out[j].Tag
	})
	return out
}

// Archives groups all of a user's blog posts by year (descending), each year's
// posts ordered by the blog's sort field.
func (r *Renderer) Archives(ctx context.Context, uid oid.OID, sortField string, isAsc bool) []*Archive {
	sortField = safeSortField(sortField)
	opt := options.Find().SetSort(bson.D{{Key: sortField, Value: sortDir(isAsc)}})
	notes := r.findNotes(ctx, blogFilter(uid), opt)
	arcs := []*Archive{}
	byYear := map[int]*Archive{}
	for _, n := range notes {
		t := postTimeOf(n, sortField)
		y := t.Year()
		arc := byYear[y]
		if arc == nil {
			arc = &Archive{Year: y}
			byYear[y] = arc
			arcs = append(arcs, arc)
		}
		arc.Posts = append(arc.Posts, fixPost(n, "", ""))
	}
	return arcs
}

// RecentPosts is the newest n posts by update time (sidebar "recent posts").
func (r *Renderer) RecentPosts(ctx context.Context, uid oid.OID, n int) []*Post {
	_, posts := r.ListBlogs(ctx, uid, oid.OID{}, 1, n, "UpdatedTime", false, false)
	return posts
}

// SearchBlogs matches a keyword against post titles (case-insensitive).
func (r *Renderer) SearchBlogs(ctx context.Context, uid oid.OID, key string, page, pageSize int, sortField string, isAsc bool) (types.Page, []*Post) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}
	sortField = safeSortField(sortField)
	filter := blogFilter(uid)
	if key != "" {
		filter["Title"] = bson.M{"$regex": regexEscape(key), "$options": "i"}
	}
	count, _ := r.DB.Notes.CountDocuments(ctx, filter)
	opt := options.Find().SetSort(bson.D{{Key: sortField, Value: sortDir(isAsc)}}).
		SetSkip(int64((page - 1) * pageSize)).SetLimit(int64(pageSize))
	posts := r.notesToPosts(ctx, r.findNotes(ctx, filter, opt), false)
	return types.NewPage(page, pageSize, int(count), posts), posts
}

// SearchByTag lists every blog post carrying tag.
func (r *Renderer) SearchByTag(ctx context.Context, uid oid.OID, tag, sortField string, isAsc bool) []*Post {
	sortField = safeSortField(sortField)
	filter := blogFilter(uid)
	filter["Tags"] = tag
	opt := options.Find().SetSort(bson.D{{Key: sortField, Value: sortDir(isAsc)}})
	return r.notesToPosts(ctx, r.findNotes(ctx, filter, opt), false)
}

// PreNextBlog returns the previous and next posts relative to baseTime under the
// blog's sort order (mirrors BlogService.PreNextBlog). baseTime is a time.Time
// for time sort fields, or a string when sorting by Title.
func (r *Renderer) PreNextBlog(ctx context.Context, uid oid.OID, sortField string, isAsc bool, noteId oid.OID, baseTime any) (*Post, *Post) {
	sortField = safeSortField(sortField)
	var preCond, nextCond bson.M
	var preDir, nextDir int
	if !isAsc { // descending blog
		preCond, preDir = bson.M{"$gte": baseTime}, 1
		nextCond, nextDir = bson.M{"$lte": baseTime}, -1
	} else {
		preCond, preDir = bson.M{"$lte": baseTime}, -1
		nextCond, nextDir = bson.M{"$gte": baseTime}, 1
	}
	findOne := func(cond bson.M, dir int, exclude []oid.OID) *Post {
		q := blogFilter(uid)
		q[sortField] = cond
		q["_id"] = bson.M{"$nin": exclude}
		var n models.Note
		opt := options.FindOne().SetSort(bson.D{{Key: sortField, Value: dir}})
		if err := r.DB.Notes.FindOne(ctx, q, opt).Decode(&n); err != nil {
			return nil
		}
		return fixPost(n, "", "")
	}
	pre := findOne(preCond, preDir, []oid.OID{noteId})
	exclude := []oid.OID{noteId}
	if pre != nil {
		if o, ok := oid.Parse(pre.NoteId); ok {
			exclude = append(exclude, o)
		}
	}
	next := findOne(nextCond, nextDir, exclude)
	return pre, next
}

// Cates returns the user's blog categories as two-level maps (top notebooks that
// hold blog posts, each with its blog-bearing children). Mirrors getCates.
func (r *Renderer) Cates(ctx context.Context, uid oid.OID) []map[string]any {
	notebooks := r.userNotebooks(ctx, uid)
	byId := map[string]models.Notebook{}
	children := map[string][]models.Notebook{}
	for _, nb := range notebooks {
		byId[nb.NotebookId.Hex()] = nb
		if !nb.ParentNotebookId.IsZero() {
			pid := nb.ParentNotebookId.Hex()
			children[pid] = append(children[pid], nb)
		}
	}
	count := func(nbHex string) int {
		o, ok := oid.Parse(nbHex)
		if !ok {
			return 0
		}
		n, _ := r.DB.Notes.CountDocuments(ctx, bson.M{"NotebookId": o, "IsBlog": true, "IsTrash": false, "IsDeleted": bson.M{"$ne": true}})
		return int(n)
	}
	// ownCount memoizes each notebook's own post count; subtreeCount sums a
	// notebook plus all descendants so a category's count matches what its page
	// lists (parent cate pages include sub-category posts — see PostsByCate).
	ownCount := map[string]int{}
	countOwn := func(nbHex string) int {
		if v, ok := ownCount[nbHex]; ok {
			return v
		}
		v := count(nbHex)
		ownCount[nbHex] = v
		return v
	}
	var subtreeCount func(nbHex string, seen map[string]bool) int
	subtreeCount = func(nbHex string, seen map[string]bool) int {
		if seen[nbHex] {
			return 0
		}
		seen[nbHex] = true
		total := countOwn(nbHex)
		for _, ch := range children[nbHex] {
			total += subtreeCount(ch.NotebookId.Hex(), seen)
		}
		return total
	}
	cates := []map[string]any{}
	for _, nb := range notebooks {
		if !nb.ParentNotebookId.IsZero() {
			continue // only top-level here
		}
		id := nb.NotebookId.Hex()
		c := subtreeCount(id, map[string]bool{})
		subs := []map[string]any{}
		for _, ch := range children[id] {
			if cc := subtreeCount(ch.NotebookId.Hex(), map[string]bool{}); cc > 0 {
				subs = append(subs, map[string]any{
					"Title": ch.Title, "UrlTitle": cateSeg(ch.UrlTitle, ch.NotebookId.Hex()), "CateId": ch.NotebookId.Hex(), "CateCount": cc,
				})
			}
		}
		if c == 0 && len(subs) == 0 {
			continue
		}
		sort.Slice(subs, func(i, j int) bool { return subs[i]["Title"].(string) < subs[j]["Title"].(string) })
		cates = append(cates, map[string]any{
			"Title": nb.Title, "UrlTitle": cateSeg(nb.UrlTitle, id), "CateId": id,
			"CateCount": c, "SubCates": subs, "SubCateCount": len(subs),
		})
	}
	sort.Slice(cates, func(i, j int) bool { return cates[i]["Title"].(string) < cates[j]["Title"].(string) })
	return cates
}

// PostsByCate lists a category's posts — the notebook plus all its descendants,
// so a parent category page includes its sub-categories' posts. Mirrors leanote,
// which stores each note's full ancestor chain in Cates and queries it; we have
// no stored chain, so we expand the subtree (same as ListBlogs for the index).
func (r *Renderer) PostsByCate(ctx context.Context, uid, notebookId oid.OID, sortField string, isAsc bool) []*Post {
	sortField = safeSortField(sortField)
	filter := blogFilter(uid)
	filter["NotebookId"] = bson.M{"$in": r.subtreeNotebookIDs(ctx, uid, notebookId)}
	opt := options.Find().SetSort(bson.D{{Key: sortField, Value: sortDir(isAsc)}})
	return r.notesToPosts(ctx, r.findNotes(ctx, filter, opt), false)
}

// cateSeg is the URL segment a theme uses for a category link
// ({{cateUrl}}/{{.UrlTitle}}): the notebook UrlTitle, falling back to its hex id
// when unset, so the emitted link is always non-empty and resolvable.
func cateSeg(urlTitle, hexId string) string {
	if urlTitle != "" {
		return urlTitle
	}
	return hexId
}

// resolveCate maps a category URL segment to a notebook id. Theme links use the
// notebook UrlTitle ({{cateUrl}}/{{.UrlTitle}}), so try an exact UrlTitle match
// (scoped to the user) first, then fall back to a raw hex id (static generation /
// direct id links).
func (r *Renderer) resolveCate(ctx context.Context, uid oid.OID, seg string) (oid.OID, bool) {
	if seg == "" {
		return oid.OID{}, false
	}
	var nb models.Notebook
	if err := r.DB.Notebooks.FindOne(ctx, bson.M{"UserId": uid, "UrlTitle": seg}).Decode(&nb); err == nil && !nb.NotebookId.IsZero() {
		return nb.NotebookId, true
	}
	if o, ok := oid.Parse(seg); ok {
		return o, true
	}
	return oid.OID{}, false
}

// Singles returns the user's blog single-pages list ([{SingleId,Title,UrlTitle}]).
func (r *Renderer) Singles(ctx context.Context, ub models.UserBlog) []map[string]string {
	if ub.Singles == nil {
		return []map[string]string{}
	}
	return ub.Singles
}

// GetSingle loads one single-page body by id or url title.
func (r *Renderer) GetSingle(ctx context.Context, uid oid.OID, idOrUrl string) (models.BlogSingle, bool) {
	var s models.BlogSingle
	if o, ok := oid.Parse(idOrUrl); ok {
		if err := r.DB.BlogSingles.FindOne(ctx, bson.M{"_id": o}).Decode(&s); err == nil {
			return s, true
		}
	}
	if err := r.DB.BlogSingles.FindOne(ctx, bson.M{"UserId": uid, "UrlTitle": idOrUrl}).Decode(&s); err == nil {
		return s, true
	}
	return s, false
}

// ----- helpers -----

func (r *Renderer) findNotes(ctx context.Context, filter bson.M, opt *options.FindOptions) []models.Note {
	notes := []models.Note{}
	cur, err := r.DB.Notes.Find(ctx, filter, opt)
	if err != nil {
		return notes
	}
	defer cur.Close(ctx)
	_ = cur.All(ctx, &notes)
	if notes == nil {
		return []models.Note{}
	}
	return notes
}

func (r *Renderer) userNotebooks(ctx context.Context, uid oid.OID) []models.Notebook {
	notebooks := []models.Notebook{}
	if cur, err := r.DB.Notebooks.Find(ctx, bson.M{"UserId": uid, "IsDeleted": bson.M{"$ne": true}}); err == nil {
		defer cur.Close(ctx)
		_ = cur.All(ctx, &notebooks)
	}
	if notebooks == nil {
		return []models.Notebook{}
	}
	return notebooks
}

// subtreeNotebookIDs returns a notebook plus all descendants (cycle-safe), so a
// category query covers sub-notebooks (matches handler.notebookSubtreeOIDs).
func (r *Renderer) subtreeNotebookIDs(ctx context.Context, uid, root oid.OID) []oid.OID {
	children := map[string][]string{}
	for _, nb := range r.userNotebooks(ctx, uid) {
		if !nb.ParentNotebookId.IsZero() {
			pid := nb.ParentNotebookId.Hex()
			children[pid] = append(children[pid], nb.NotebookId.Hex())
		}
	}
	out := []oid.OID{}
	seen := map[string]bool{}
	stack := []string{root.Hex()}
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[id] {
			continue
		}
		seen[id] = true
		if o, ok := oid.Parse(id); ok {
			out = append(out, o)
		}
		stack = append(stack, children[id]...)
	}
	return out
}

// notesToPosts builds posts and joins each one's abstract (and, if withContent,
// full content) from note_contents in one round-trip.
func (r *Renderer) notesToPosts(ctx context.Context, notes []models.Note, withContent bool) []*Post {
	posts := make([]*Post, 0, len(notes))
	if len(notes) == 0 {
		return posts
	}
	ids := make([]oid.OID, len(notes))
	for i, n := range notes {
		ids[i] = n.NoteId
	}
	contents := r.noteContents(ctx, ids)
	for _, n := range notes {
		abstract, content := "", ""
		if nc, ok := contents[n.NoteId.Hex()]; ok {
			abstract = nc.Abstract
			if withContent {
				content = nc.Content
			}
		}
		posts = append(posts, fixPost(n, abstract, content))
	}
	return posts
}

// oneNoteToPost builds a single post with full content and its category
// breadcrumb (only the detail page needs Cates; list pages skip the extra
// lookups).
func (r *Renderer) oneNoteToPost(ctx context.Context, n models.Note) *Post {
	var nc models.NoteContent
	_ = r.DB.NoteContents.FindOne(ctx, bson.M{"_id": n.NoteId}).Decode(&nc)
	p := fixPost(n, nc.Abstract, nc.Content)
	p.Cates = r.notebookBreadcrumb(ctx, n.UserId, n.NotebookId)
	return p
}

// notebookBreadcrumb returns a post's category breadcrumb: the chain of notebooks
// from the top-level ancestor down to the post's own notebook (root-first), each
// linkable by UrlTitle ({{$.cateUrl}}/{{.UrlTitle}}). Mirrors leanote's
// NotebookService.GetNotebookIdsAndTitles; capped at 10 levels to bound cycles.
func (r *Renderer) notebookBreadcrumb(ctx context.Context, uid, notebookId oid.OID) []CateRef {
	chain := []CateRef{}
	id := notebookId
	for i := 0; i < 10 && !id.IsZero(); i++ {
		var nb models.Notebook
		if err := r.DB.Notebooks.FindOne(ctx, bson.M{"_id": id, "UserId": uid}).Decode(&nb); err != nil {
			break
		}
		hex := nb.NotebookId.Hex()
		chain = append(chain, CateRef{
			Title:    nb.Title,
			UrlTitle: cateSeg(nb.UrlTitle, hex),
			CateId:   hex,
		})
		id = nb.ParentNotebookId
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 { // reverse → root-first
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

func (r *Renderer) noteContents(ctx context.Context, ids []oid.OID) map[string]models.NoteContent {
	out := map[string]models.NoteContent{}
	cur, err := r.DB.NoteContents.Find(ctx, bson.M{"_id": bson.M{"$in": ids}})
	if err != nil {
		return out
	}
	defer cur.Close(ctx)
	var list []models.NoteContent
	_ = cur.All(ctx, &list)
	for _, nc := range list {
		out[nc.NoteId.Hex()] = nc
	}
	return out
}

// fixPost converts a note into a Post, defaulting UrlTitle to the post title
// (then the note id) and dropping the [""] placeholder tag slice.
func fixPost(n models.Note, abstract, content string) *Post {
	urlTitle := n.UrlTitle
	if urlTitle == "" {
		urlTitle = strings.TrimSpace(n.Title)
	}
	if urlTitle == "" {
		urlTitle = n.NoteId.Hex()
	}
	tags := n.Tags
	if len(tags) == 1 && tags[0] == "" {
		tags = nil
	}
	p := &Post{
		NoteId:      n.NoteId.Hex(),
		NotebookId:  n.NotebookId.Hex(),
		Title:       n.Title,
		UrlTitle:    urlTitle,
		ImgSrc:      n.ImgSrc,
		CreatedTime: n.CreatedTime,
		UpdatedTime: n.UpdatedTime,
		PublicTime:  n.PublicTime,
		Desc:        n.Desc,
		Abstract:    abstract,
		Content:     content,
		Tags:        tags,
		CommentNum:  n.CommentNum,
		ReadNum:     n.ReadNum,
		LikeNum:     n.LikeNum,
		IsMarkdown:  n.IsMarkdown,
		IsTop:       n.IsTop,
	}
	return p
}

func postTimeOf(n models.Note, sortField string) time.Time {
	switch sortField {
	case "CreatedTime":
		return n.CreatedTime
	case "UpdatedTime":
		return n.UpdatedTime
	default:
		return n.PublicTime
	}
}

// regexEscape quotes regex metacharacters in a user keyword.
func regexEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\.+*?()|[]{}^$`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
