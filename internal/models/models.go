// Package models mirrors the legacy leanote BSON documents (app/info/*.go).
// bson tags MUST match the PascalCase field names actually stored in MongoDB
// (confirmed via probe). ObjectId fields use oid.OID so zero values serialize
// to "" in JSON while remaining real BSON ObjectIds on disk.
package models

import (
	"time"

	"leanote/internal/oid"
)

// ----- Note & content -----

type Note struct {
	NoteId        oid.OID   `bson:"_id,omitempty" json:"NoteId"`
	UserId        oid.OID   `bson:"UserId" json:"UserId"`
	CreatedUserId oid.OID   `bson:"CreatedUserId,omitempty" json:"CreatedUserId"`
	NotebookId    oid.OID   `bson:"NotebookId" json:"NotebookId"`
	Title         string    `bson:"Title" json:"Title"`
	Desc          string    `bson:"Desc" json:"Desc"`
	Src           string    `bson:"Src,omitempty" json:"Src"`
	ImgSrc        string    `bson:"ImgSrc" json:"ImgSrc"`
	Tags          []string  `bson:"Tags,omitempty" json:"Tags"`
	IsTrash       bool      `bson:"IsTrash" json:"IsTrash"`
	IsBlog        bool      `bson:"IsBlog,omitempty" json:"IsBlog"`
	UrlTitle      string    `bson:"UrlTitle,omitempty" json:"UrlTitle"`
	IsTop         bool      `bson:"IsTop,omitempty" json:"IsTop"`
	ReadNum       int       `bson:"ReadNum,omitempty" json:"ReadNum"`
	LikeNum       int       `bson:"LikeNum,omitempty" json:"LikeNum"`
	CommentNum    int       `bson:"CommentNum,omitempty" json:"CommentNum"`
	IsMarkdown    bool      `bson:"IsMarkdown" json:"IsMarkdown"`
	AttachNum     int       `bson:"AttachNum" json:"AttachNum"`
	CreatedTime   time.Time `bson:"CreatedTime" json:"CreatedTime"`
	UpdatedTime   time.Time `bson:"UpdatedTime" json:"UpdatedTime"`
	PublicTime    time.Time `bson:"PublicTime,omitempty" json:"PublicTime"`
	UpdatedUserId oid.OID   `bson:"UpdatedUserId" json:"-"`
	Usn           int       `bson:"Usn" json:"Usn"`
	IsDeleted     bool      `bson:"IsDeleted" json:"IsDeleted"`
}

type NoteContent struct {
	NoteId        oid.OID   `bson:"_id,omitempty" json:"NoteId"`
	UserId        oid.OID   `bson:"UserId" json:"-"`
	IsBlog        bool      `bson:"IsBlog,omitempty" json:"IsBlog"`
	Content       string    `bson:"Content" json:"Content"`
	Abstract      string    `bson:"Abstract" json:"Abstract"`
	CreatedTime   time.Time `bson:"CreatedTime" json:"-"`
	UpdatedTime   time.Time `bson:"UpdatedTime" json:"-"`
	UpdatedUserId oid.OID   `bson:"UpdatedUserId" json:"-"`
}

// NoteDetail is the merged getNoteAndContent response: Note fields are promoted
// to the top level and the content fields are appended (frontend NoteAndContent).
type NoteDetail struct {
	Note
	Content  string `json:"Content"`
	Abstract string `json:"Abstract"`
}

// ----- Note content history -----

type EachHistory struct {
	UpdatedUserId oid.OID   `bson:"UpdatedUserId" json:"UpdatedUserId"`
	UpdatedTime   time.Time `bson:"UpdatedTime" json:"UpdatedTime"`
	Content       string    `bson:"Content" json:"Content"`
}

type NoteContentHistory struct {
	NoteId    oid.OID       `bson:"_id,omitempty" json:"NoteId"`
	UserId    oid.OID       `bson:"UserId" json:"-"`
	Histories []EachHistory `bson:"Histories" json:"Histories"`
}

// ----- Notebook -----

type Notebook struct {
	NotebookId       oid.OID     `bson:"_id,omitempty" json:"NotebookId"`
	UserId           oid.OID     `bson:"UserId" json:"UserId"`
	ParentNotebookId oid.OID     `bson:"ParentNotebookId,omitempty" json:"ParentNotebookId"`
	Seq              int         `bson:"Seq" json:"Seq"`
	Title            string      `bson:"Title" json:"Title"`
	UrlTitle         string      `bson:"UrlTitle,omitempty" json:"UrlTitle"`
	NumberNotes      int         `bson:"NumberNotes" json:"NumberNotes"`
	IsTrash          bool        `bson:"IsTrash,omitempty" json:"IsTrash"`
	IsBlog           bool        `bson:"IsBlog,omitempty" json:"IsBlog"`
	CreatedTime      time.Time   `bson:"CreatedTime,omitempty" json:"CreatedTime"`
	UpdatedTime      time.Time   `bson:"UpdatedTime,omitempty" json:"UpdatedTime"`
	Usn              int         `bson:"Usn" json:"Usn"`
	IsDeleted        bool        `bson:"IsDeleted" json:"IsDeleted"`
	Subs             []*Notebook `bson:"-" json:"Subs,omitempty"` // built in-memory, not stored
}

// ----- User -----

type User struct {
	UserId        oid.OID   `bson:"_id,omitempty" json:"UserId"`
	Email         string    `bson:"Email" json:"Email"`
	Username      string    `bson:"Username" json:"Username"`
	UsernameRaw   string    `bson:"UsernameRaw" json:"UsernameRaw"`
	Pwd           string    `bson:"Pwd" json:"-"`
	Verified      bool      `bson:"Verified" json:"Verified"`
	Logo          string    `bson:"Logo" json:"Logo"`
	Theme         string    `bson:"Theme" json:"Theme"`
	NotebookWidth int       `bson:"NotebookWidth" json:"NotebookWidth"`
	NoteListWidth int       `bson:"NoteListWidth" json:"NoteListWidth"`
	MdEditorWidth int       `bson:"MdEditorWidth" json:"MdEditorWidth"`
	LeftIsMin     bool      `bson:"LeftIsMin" json:"LeftIsMin"`
	Usn           int       `bson:"Usn" json:"-"`
	CreatedTime   time.Time `bson:"CreatedTime" json:"-"`
	// Per-user image bed (where this user's note images are stored). Each user
	// configures their own; kept out of the /user/info JSON (json:"-") since
	// ImageBeds carries S3 secrets. ImageBeds is a JSON array of imagebed.Bed.
	ImageBedType     string `bson:"ImageBedType,omitempty" json:"-"`     // local|s3
	ImageBeds        string `bson:"ImageBeds,omitempty" json:"-"`        // JSON []imagebed.Bed
	ImageBedActiveId string `bson:"ImageBedActiveId,omitempty" json:"-"` // id of the active bed
	ImagePageSize    int    `bson:"ImagePageSize,omitempty" json:"-"`    // images per page in the picker
	// IsAdmin is derived (not stored): set by UserInfo when Username matches the
	// configured admin user, so the frontend can gate the admin entry/route.
	IsAdmin bool `bson:"-" json:"IsAdmin"`
}

// ----- Global config (new app_configs collection; key is the _id) -----

type Config struct {
	Key         string    `bson:"_id" json:"Key"`
	ValueStr    string    `bson:"ValueStr,omitempty" json:"ValueStr,omitempty"`
	ValueArr    []string  `bson:"ValueArr,omitempty" json:"ValueArr,omitempty"`
	UpdatedTime time.Time `bson:"UpdatedTime" json:"-"`
}

// ----- File (image) -----

type File struct {
	FileId         oid.OID   `bson:"_id,omitempty" json:"FileId"`
	UserId         oid.OID   `bson:"UserId" json:"-"`
	AlbumId        oid.OID   `bson:"AlbumId,omitempty" json:"AlbumId"`
	Name           string    `bson:"Name" json:"Name"`
	Title          string    `bson:"Title" json:"Title"`
	Size           int64     `bson:"Size" json:"Size"`
	Type           string    `bson:"Type" json:"Type"`
	Path           string    `bson:"Path" json:"Path"`
	IsDefaultAlbum bool      `bson:"IsDefaultAlbum,omitempty" json:"-"`
	CreatedTime    time.Time `bson:"CreatedTime" json:"CreatedTime"`
}

// ----- Album -----

type Album struct {
	AlbumId     oid.OID   `bson:"_id,omitempty" json:"AlbumId"`
	UserId      oid.OID   `bson:"UserId" json:"-"`
	Name        string    `bson:"Name" json:"Name"`
	Type        int       `bson:"Type" json:"Type"`
	Seq         int       `bson:"Seq" json:"Seq"`
	CreatedTime time.Time `bson:"CreatedTime" json:"CreatedTime"`
}

// ----- Attach -----

type Attach struct {
	AttachId     oid.OID   `bson:"_id,omitempty" json:"AttachId"`
	NoteId       oid.OID   `bson:"NoteId" json:"NoteId"`
	UploadUserId oid.OID   `bson:"UploadUserId" json:"-"`
	Name         string    `bson:"Name" json:"Name"`
	Title        string    `bson:"Title" json:"Title"`
	Size         int64     `bson:"Size" json:"Size"`
	Type         string    `bson:"Type" json:"Type"`
	Path         string    `bson:"Path" json:"-"`
	CreatedTime  time.Time `bson:"CreatedTime" json:"CreatedTime"`
}

// ----- Tag (v1: one document per user, holding the tag array) -----

type Tag struct {
	UserId oid.OID  `bson:"_id" json:"-"`
	Tags   []string `bson:"Tags" json:"Tags"`
}

// ----- Session (new collection app_sessions; cookie-based auth) -----

type Session struct {
	Id          oid.OID   `bson:"_id,omitempty"`
	Token       string    `bson:"Token"`
	UserId      oid.OID   `bson:"UserId"`
	CreatedTime time.Time `bson:"CreatedTime"`
	UpdatedTime time.Time `bson:"UpdatedTime"`
}

// ----- Blog (per-user blog settings; existing leanote `user_blogs`, _id=userId) -----

// UserBlog holds one user's blog settings. Field names match the stored
// PascalCase BSON (drop-in with the legacy leanote `user_blogs` collection).
// Updates are partial ($set per submitted field) so unmanaged fields (CateIds,
// Singles, Style/Css, SubDomain/Domain) are preserved untouched.
type UserBlog struct {
	UserId      oid.OID             `bson:"_id,omitempty" json:"UserId"`
	Logo        string              `bson:"Logo" json:"Logo"`
	Title       string              `bson:"Title" json:"Title"`
	SubTitle    string              `bson:"SubTitle" json:"SubTitle"`
	AboutMe     string              `bson:"AboutMe" json:"AboutMe"`
	CanComment  bool                `bson:"CanComment" json:"CanComment"`
	CommentType string              `bson:"CommentType" json:"CommentType"` // default | disqus
	DisqusId    string              `bson:"DisqusId" json:"DisqusId"`
	Style       string              `bson:"Style,omitempty" json:"Style"`
	Css         string              `bson:"Css,omitempty" json:"Css"`
	ThemeId     oid.OID             `bson:"ThemeId,omitempty" json:"ThemeId"`
	ThemePath   string              `bson:"ThemePath,omitempty" json:"-"`
	PerPageSize int                 `bson:"PerPageSize,omitempty" json:"PerPageSize"`
	SortField   string              `bson:"SortField,omitempty" json:"SortField"`
	IsAsc       bool                `bson:"IsAsc,omitempty" json:"IsAsc"`
	SubDomain   string              `bson:"SubDomain,omitempty" json:"SubDomain"`
	Domain      string              `bson:"Domain,omitempty" json:"Domain"`
	CateIds     []string            `bson:"CateIds,omitempty" json:"-"`
	Singles     []map[string]string `bson:"Singles,omitempty" json:"-"`

	// BlogType selects how the blog is delivered: "dynamic" (this server renders
	// /blog/<user> live) or "static" (generate a static site + deploy to GitHub
	// Pages). Empty defaults to dynamic. New fields, all omitempty → drop-in safe.
	BlogType string `bson:"BlogType,omitempty" json:"BlogType"`
	// GitHub Pages deploy config (used when BlogType=="static"). GhToken is a
	// Personal Access Token; it is a secret and is NEVER serialized to JSON.
	GhRepo     string    `bson:"GhRepo,omitempty" json:"GhRepo"`         // owner/name
	GhBranch   string    `bson:"GhBranch,omitempty" json:"GhBranch"`     // default gh-pages
	GhToken    string    `bson:"GhToken,omitempty" json:"-"`             // PAT (secret)
	GhDomain   string    `bson:"GhDomain,omitempty" json:"GhDomain"`     // CNAME custom domain
	GhBasePath string    `bson:"GhBasePath,omitempty" json:"GhBasePath"` // "" or "/repo"
	GhEmail    string    `bson:"GhEmail,omitempty" json:"GhEmail"`       // committer email
	LastDeploy time.Time `bson:"LastDeploy,omitempty" json:"LastDeploy"`
}

// BlogSingle is a blog single-page (existing leanote `blog_singles`). Body is
// rendered the same way as a post (markdown handled client-side by the theme).
type BlogSingle struct {
	SingleId    oid.OID   `bson:"_id,omitempty" json:"SingleId"`
	UserId      oid.OID   `bson:"UserId" json:"-"`
	Title       string    `bson:"Title" json:"Title"`
	UrlTitle    string    `bson:"UrlTitle,omitempty" json:"UrlTitle"`
	Content     string    `bson:"Content" json:"Content"`
	IsMarkdown  bool      `bson:"IsMarkdown,omitempty" json:"IsMarkdown"`
	CreatedTime time.Time `bson:"CreatedTime,omitempty" json:"-"`
	UpdatedTime time.Time `bson:"UpdatedTime,omitempty" json:"-"`
}

// ----- Theme (existing leanote `themes`; file-based blog themes on disk) -----

// Theme is one blog theme. Its files live on disk under Path (relative to
// FILE_ROOT, e.g. public/upload/<digest3>/<userId>/themes/<themeId>). Info is
// the parsed theme.json. Drop-in with the legacy `themes` collection.
type Theme struct {
	ThemeId     oid.OID        `bson:"_id,omitempty" json:"ThemeId"`
	UserId      oid.OID        `bson:"UserId" json:"-"`
	Name        string         `bson:"Name" json:"Name"`
	Version     string         `bson:"Version" json:"Version"`
	Author      string         `bson:"Author" json:"Author"`
	AuthorUrl   string         `bson:"AuthorUrl" json:"AuthorUrl"`
	Path        string         `bson:"Path" json:"-"`
	Info        map[string]any `bson:"Info,omitempty" json:"-"`
	IsActive    bool           `bson:"IsActive" json:"IsActive"`
	IsDefault   bool           `bson:"IsDefault,omitempty" json:"IsDefault"`
	Style       string         `bson:"Style,omitempty" json:"-"`
	CreatedTime time.Time      `bson:"CreatedTime,omitempty" json:"-"`
	UpdatedTime time.Time      `bson:"UpdatedTime,omitempty" json:"-"`
}
