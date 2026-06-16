// Package router wires all application routes. Paths match the existing frontend
// contract exactly (see web-src/src/api/endpoints.ts). It is a package (not
// main) so integration checks can register the exact production routing.
package router

import (
	"path/filepath"

	"github.com/gofiber/fiber/v2"

	"leanote/config"
	"leanote/internal/auth"
	"leanote/internal/db"
	"leanote/internal/handler"
)

func Register(app *fiber.App, cfg config.Config, database *db.DB) {
	h := handler.New(cfg, database)

	// Host-based blog routing: when the request Host is a user's blog subdomain
	// or custom domain, serve the blog at the host root. Registered first (before
	// auth and the SPA fallback) so a blog host's "/" is intercepted; app hosts
	// fall straight through with no DB lookup.
	app.Use(h.HostBlogMiddleware())

	// Resolve the session cookie → user id for every request.
	app.Use(auth.Middleware(database))

	// Protected route helper: attaches RequireAuth per-route (so static assets
	// and unmatched paths are NOT swept into an auth wall).
	prot := func(method, path string, handler fiber.Handler) {
		app.Add(method, path, auth.RequireAuth, handler)
	}

	// Admin route helper: RequireAuth then RequireAdmin (403 for non-admins).
	adm := func(method, path string, handler fiber.Handler) {
		app.Add(method, path, auth.RequireAuth, h.RequireAdmin, handler)
	}

	// ----- static (avatars/uploads), public -----
	root := cfg.FileRoot
	app.Static("/public", filepath.Join(root, "public"))
	app.Static("/upload", filepath.Join(root, "public", "upload"))

	// ----- auth (public) -----
	app.Post("/doLogin", h.DoLogin)
	app.Get("/logout", h.Logout)
	app.Post("/doRegister", h.DoRegister)
	app.Post("/doFindPassword", h.DoFindPassword)
	app.Post("/findPasswordUpdate", h.FindPasswordUpdate)

	// ----- current user -----
	prot("GET", "/user/info", h.UserInfo)

	// ----- user settings -----
	prot("POST", "/user/updateUsername", h.UpdateUsername)
	prot("POST", "/user/updatePwd", h.UpdatePwd)
	prot("POST", "/user/updateTheme", h.UpdateTheme)
	prot("POST", "/user/updateColumnWidth", h.UpdateColumnWidth)
	prot("POST", "/user/updateLeftIsMin", h.UpdateLeftIsMin)
	prot("POST", "/user/reSendActiveEmail", h.ReSendActiveEmail)

	// ----- per-user image bed settings -----
	prot("GET", "/user/imageBedSettings", h.UserImageBedSettings)
	prot("POST", "/user/updateImageBedSettings", h.UpdateImageBedSettings)
	prot("POST", "/user/presignBedTest", h.PresignBedTest)

	// ----- per-user blog + theme settings -----
	prot("GET", "/user/blogSettings", h.BlogSettings)
	prot("POST", "/user/updateBlogSettings", h.UpdateBlogSettings)
	prot("GET", "/user/themes", h.Themes)
	prot("POST", "/user/activeTheme", h.ActiveTheme)
	prot("POST", "/user/deleteTheme", h.DeleteTheme)
	prot("GET", "/user/themeFiles", h.ThemeFiles)
	prot("GET", "/user/themeFile", h.ThemeFile)
	prot("POST", "/user/updateThemeFile", h.UpdateThemeFile)
	prot("POST", "/user/deleteThemeFile", h.DeleteThemeFile)
	prot("POST", "/user/uploadThemeImage", h.UploadThemeImage)
	prot("POST", "/user/importTheme", h.ImportTheme)
	prot("GET", "/user/exportTheme", h.ExportTheme)

	// ----- static blog deploy (GitHub Pages) -----
	prot("GET", "/user/blogDeploySettings", h.BlogDeploySettings)
	prot("POST", "/user/updateBlogDeploySettings", h.UpdateBlogDeploySettings)
	prot("POST", "/user/publishBlog", h.PublishBlog)
	prot("GET", "/user/downloadBlogZip", h.DownloadBlogZip)

	// ----- notebooks -----
	prot("GET", "/notebook/getNotebooks", h.GetNotebooks)
	prot("POST", "/notebook/addNotebook", h.AddNotebook)
	prot("POST", "/notebook/updateNotebookTitle", h.UpdateNotebookTitle)
	prot("GET", "/notebook/deleteNotebook", h.DeleteNotebook)
	prot("POST", "/notebook/dragNotebooks", h.DragNotebooks)

	// ----- notes -----
	prot("GET", "/note/listNotes", h.ListNotes)
	prot("GET", "/note/listTrashNotes", h.ListTrashNotes)
	prot("GET", "/note/getNoteAndContent", h.GetNoteAndContent)
	prot("GET", "/note/getNoteContent", h.GetNoteContent)
	prot("POST", "/note/updateNoteOrContent", h.UpdateNoteOrContent)
	prot("POST", "/note/deleteNote", h.DeleteNote)
	prot("POST", "/note/restoreNote", h.RestoreNote)
	prot("POST", "/note/deleteTrash", h.DeleteTrash)
	prot("POST", "/note/moveNote", h.MoveNote)
	prot("POST", "/note/copyNote", h.CopyNote)
	prot("POST", "/note/searchNote", h.SearchNote) // POST only (frontend contract)
	prot("GET", "/note/searchNoteByTags", h.SearchNoteByTags)
	prot("POST", "/note/setNote2Blog", h.SetNote2Blog)
	prot("POST", "/note/updateBlogMeta", h.UpdateBlogMeta)

	// ----- note content history -----
	prot("GET", "/noteContentHistory/listHistories", h.ListHistories)

	// ----- tags -----
	prot("POST", "/tag/updateTag", h.UpdateTag)
	prot("POST", "/tag/deleteTag", h.DeleteTag)

	// ----- images / files -----
	prot("POST", "/file/pasteImage", h.PasteImage)
	prot("POST", "/file/uploadImageLeaui", h.UploadImageLeaui)
	prot("POST", "/file/uploadAvatar", h.UploadAvatar)
	prot("GET", "/file/getImages", h.GetImages)
	prot("POST", "/file/updateImageTitle", h.UpdateImageTitle)
	prot("POST", "/file/deleteImage", h.DeleteImage)
	prot("GET", "/file/outputImage", h.OutputImage)
	prot("GET", "/file/imageBedConfig", h.ImageBedConfig)
	prot("POST", "/file/presignImage", h.PresignImage)
	prot("GET", "/file/bedImages", h.BedImages)
	prot("POST", "/file/bedDeleteObject", h.BedDeleteObject)
	prot("POST", "/file/bedCreatePrefix", h.BedCreatePrefix)
	prot("POST", "/file/bedDeletePrefix", h.BedDeletePrefix)
	prot("POST", "/file/bedRenamePrefix", h.BedRenamePrefix)

	// ----- albums -----
	prot("GET", "/album/getAlbums", h.GetAlbums)
	prot("POST", "/album/addAlbum", h.AddAlbum)
	prot("POST", "/album/updateAlbum", h.UpdateAlbum)
	prot("POST", "/album/deleteAlbum", h.DeleteAlbum)

	// ----- attachments -----
	prot("GET", "/attach/getAttachs", h.GetAttachs)
	prot("POST", "/attach/uploadAttach", h.UploadAttach)
	prot("POST", "/attach/deleteAttach", h.DeleteAttach)
	prot("GET", "/attach/download", h.Download)

	// ----- admin (admin user only) -----
	adm("GET", "/admin/stats", h.AdminStats)
	adm("GET", "/admin/listUsers", h.AdminListUsers)
	adm("POST", "/admin/addUser", h.AdminAddUser)
	adm("POST", "/admin/resetPwd", h.AdminResetPwd)
	adm("GET", "/admin/getConfigs", h.AdminGetConfigs)
	adm("POST", "/admin/updateConfigs", h.AdminUpdateConfigs)

	// ----- public blog (no auth; only serves live when BlogType=dynamic) -----
	// Register the owner preview (auth) and all fixed-prefix routes BEFORE the
	// /blog/:userIdOrEmail catch-all so they aren't shadowed.
	prot("GET", "/blog/preview", h.BlogPreviewIndex)
	prot("GET", "/blog/preview/post/:noteId", h.BlogPreviewPost)
	prot("GET", "/blog/preview/cate/:notebookId", h.BlogPreviewCate)
	prot("GET", "/blog/preview/cates", h.BlogPreviewCates)
	prot("GET", "/blog/preview/tags", h.BlogPreviewTags)
	prot("GET", "/blog/preview/tag/:tag", h.BlogPreviewTag)
	prot("GET", "/blog/preview/archives", h.BlogPreviewArchives)
	prot("GET", "/blog/preview/search", h.BlogPreviewSearch)
	prot("GET", "/blog/preview/single/:singleId", h.BlogPreviewSingle)

	app.Get("/blog", h.BlogIndex)
	app.Get("/blog/image/:fileId", h.BlogImage)
	app.Get("/blog/post/:userIdOrEmail/:noteId", h.BlogPost)
	app.Get("/blog/post/:noteId", h.BlogPost)
	app.Get("/blog/cate/:userIdOrEmail/:notebookId", h.BlogCate)
	app.Get("/blog/cates/:userIdOrEmail", h.BlogCates)
	app.Get("/blog/tags/:userIdOrEmail", h.BlogTags)
	app.Get("/blog/tag/:userIdOrEmail/:tag", h.BlogTag)
	app.Get("/blog/archives/:userIdOrEmail", h.BlogArchives)
	app.Get("/blog/search/:userIdOrEmail/:keywords", h.BlogSearch)
	app.Get("/blog/search/:userIdOrEmail", h.BlogSearch)
	app.Get("/blog/single/:userIdOrEmail/:singleId", h.BlogSingle)
	app.Get("/blog/rss/:userIdOrEmail", h.BlogRSS)
	app.Get("/blog/sitemap/:userIdOrEmail", h.BlogSitemap)
	app.Get("/blog/sitemap.xml", h.BlogSitemap)
	app.Get("/blog/:userIdOrEmail", h.BlogIndex) // catch-all, must be last
}
