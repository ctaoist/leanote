package handler

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"leanote/internal/imagebed"
	"leanote/internal/models"
	"leanote/internal/types"
	"leanote/internal/web"
)

// loadUser loads the authenticated user document. RequireAuth runs first, so the
// id is normally present; it still guards the zero case defensively.
func (h *Handler) loadUser(c *fiber.Ctx) (models.User, error) {
	var u models.User
	uid := web.UserOID(c)
	if uid.IsZero() {
		return u, fiber.ErrUnauthorized
	}
	err := h.DB.Users.FindOne(c.Context(), bson.M{"_id": uid}).Decode(&u)
	return u, err
}

// UserImageBedSettings returns the current user's image-bed settings for the
// settings form, including secret keys (the user's own credentials) so the form
// can round-trip them. This is the per-user replacement for the old admin-level
// global config; every logged-in user configures their own bed.
func (h *Handler) UserImageBedSettings(c *fiber.Ctx) error {
	u, err := h.loadUser(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrRe("未登录"))
	}
	beds := userImageBeds(u)
	if beds == nil {
		beds = []imagebed.Bed{}
	}
	id := u.ImageBedActiveId
	if id == "" && len(beds) > 0 {
		id = beds[0].ID
	}
	return c.JSON(types.OkItem(fiber.Map{
		"imageBedType":     userImageBedType(u),
		"imageBedActiveId": id,
		"imageBeds":        beds,
		"imagePageSize":    userImagePageSize(u),
		// Admin master switch: when false, the user may not select/save "local".
		"allowLocalImageBed": h.cfgBool(c.Context(), cfgAllowLocalImageBed, true),
	}))
}

// UpdateImageBedSettings validates and saves the submitted image-bed settings to
// the current user's document. Validation runs before any write, so a rejected
// update commits nothing.
func (h *Handler) UpdateImageBedSettings(c *fiber.Ctx) error {
	u, err := h.loadUser(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrRe("未登录"))
	}
	set, msg := parseImageBedForm(c, u, h.cfgBool(c.Context(), cfgAllowLocalImageBed, true))
	if msg != "" {
		return c.JSON(types.ErrRe(msg))
	}
	if _, err := h.DB.Users.UpdateOne(c.Context(), bson.M{"_id": u.UserId},
		bson.M{"$set": set}); err != nil {
		return c.JSON(types.ErrRe("保存失败"))
	}
	return c.JSON(types.OkRe())
}

// parseImageBedForm reads the submitted image-bed fields (falling back to the
// user's current values for any field not present), normalizes and validates the
// beds, and returns the $set map to apply. A non-empty message means the
// effective config is invalid (no map should be written).
func parseImageBedForm(c *fiber.Ctx, cur models.User, allowLocal bool) (bson.M, string) {
	// Effective master switch: submitted else current.
	effType := userImageBedType(cur)
	if web.Has(c, "imageBedType") {
		effType = strings.ToLower(strings.TrimSpace(c.FormValue("imageBedType")))
	}
	if effType != "s3" {
		effType = "local"
	}
	// Admin gate: local storage may be disabled site-wide.
	if effType == "local" && !allowLocal {
		return nil, "管理员已禁用本地图床，请配置 S3 图床"
	}

	// Effective beds: parse submitted JSON else keep current.
	beds := userImageBeds(cur)
	if web.Has(c, "imageBeds") {
		raw := strings.TrimSpace(c.FormValue("imageBeds"))
		if raw == "" {
			raw = "[]"
		}
		var parsed []imagebed.Bed
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			return nil, "图床配置格式错误"
		}
		beds = parsed
	}
	if beds == nil {
		beds = []imagebed.Bed{}
	}
	// Normalize: trim fields, assign ids, default signMode.
	for i := range beds {
		beds[i].Name = strings.TrimSpace(beds[i].Name)
		beds[i].Endpoint = strings.TrimSpace(beds[i].Endpoint)
		beds[i].Region = strings.TrimSpace(beds[i].Region)
		beds[i].Bucket = strings.TrimSpace(beds[i].Bucket)
		beds[i].AccessKey = strings.TrimSpace(beds[i].AccessKey)
		beds[i].SecretKey = strings.TrimSpace(beds[i].SecretKey)
		beds[i].PublicBaseURL = strings.TrimSpace(beds[i].PublicBaseURL)
		beds[i].KeyPrefix = strings.TrimSpace(beds[i].KeyPrefix)
		if beds[i].ID == "" {
			beds[i].ID = primitive.NewObjectID().Hex()
		}
		if beds[i].SignMode != "server" {
			beds[i].SignMode = "client"
		}
	}

	// Effective active id: submitted else current; must resolve to a bed.
	activeID := cur.ImageBedActiveId
	if web.Has(c, "imageBedActiveId") {
		activeID = strings.TrimSpace(c.FormValue("imageBedActiveId"))
	}
	resolves := false
	for _, b := range beds {
		if b.ID == activeID {
			resolves = true
			break
		}
	}
	if !resolves && len(beds) > 0 {
		activeID = beds[0].ID
	}

	// Effective page size: submitted (validated) else current.
	pageSize := cur.ImagePageSize
	if web.Has(c, "imagePageSize") {
		n, err := strconv.Atoi(strings.TrimSpace(c.FormValue("imagePageSize")))
		if err != nil || n < 1 {
			return nil, "每页图片数必须为正整数"
		}
		if n > 100 {
			n = 100
		}
		pageSize = n
	}

	// Validate before any write.
	if effType == "s3" {
		if len(beds) == 0 {
			return nil, "请至少配置一个图床"
		}
		for _, b := range beds {
			if b.Endpoint == "" || b.Bucket == "" || b.AccessKey == "" || b.SecretKey == "" {
				return nil, "请填写完整的 S3 配置"
			}
		}
	}

	blob, _ := json.Marshal(beds)
	return bson.M{
		"ImageBedType":     effType,
		"ImageBeds":        string(blob),
		"ImageBedActiveId": activeID,
		"ImagePageSize":    pageSize,
	}, ""
}

// PresignBedTest presigns a PUT + DELETE for a 1px test object against the
// submitted (possibly unsaved) bed config. The "test connection" button uses it
// for server-sign-mode beds so it works without browser Web Crypto: the browser
// just does a plain fetch PUT/DELETE to the returned URLs (which also exercises
// the bucket's CORS, exactly like a real server-mode upload). Any logged-in user
// may test their own bed.
func (h *Handler) PresignBedTest(c *fiber.Ctx) error {
	var b imagebed.Bed
	if err := json.Unmarshal([]byte(c.FormValue("bed")), &b); err != nil {
		return c.JSON(types.ErrRe("图床配置格式错误"))
	}
	s := b.S3()
	if !s.Valid() {
		return c.JSON(types.ErrRe("请填写完整的 S3 配置"))
	}
	key := s.BuildKey("__leanote_conn_test__.png")
	putURL, err := s.PresignPut(key, 5*time.Minute)
	if err != nil {
		return c.JSON(types.ErrRe("生成测试链接失败"))
	}
	delURL, err := s.PresignDelete(key, 5*time.Minute)
	if err != nil {
		return c.JSON(types.ErrRe("生成测试链接失败"))
	}
	return c.JSON(types.OkItem(fiber.Map{"putUrl": putURL, "deleteUrl": delURL, "key": key}))
}
