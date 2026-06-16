package handler

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"

	"leanote/internal/auth"
	"leanote/internal/models"
	"leanote/internal/oid"
	"leanote/internal/types"
	"leanote/internal/web"
)

const adminUserPageSize = 10

// adminUserView is the admin user-list row. It deliberately exposes CreatedTime
// (which models.User hides from the /user/info JSON) and omits Pwd and settings.
type adminUserView struct {
	UserId      oid.OID   `json:"UserId"`
	Email       string    `json:"Email"`
	Username    string    `json:"Username"`
	Verified    bool      `json:"Verified"`
	CreatedTime time.Time `json:"CreatedTime"`
}

// RequireAdmin gates the /admin/* routes: the session user's Username must match
// the configured admin user (cfg.AdminUsername, e.g. ctaoist). It runs after
// auth.RequireAuth, so it 403s rather than 401s for ordinary logged-in users.
func (h *Handler) RequireAdmin(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	if uid.IsZero() {
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrRe("未登录"))
	}
	var u models.User
	if err := h.DB.Users.FindOne(c.Context(), bson.M{"_id": uid}).Decode(&u); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrRe("未登录"))
	}
	if u.Username != h.Cfg.AdminUsername {
		return c.Status(fiber.StatusForbidden).JSON(types.ErrRe("无权限"))
	}
	return c.Next()
}

// AdminStats returns the dashboard counts (users, live notes, blog notes).
func (h *Handler) AdminStats(c *fiber.Ctx) error {
	ctx := c.Context()
	userCount, _ := h.DB.Users.CountDocuments(ctx, bson.M{})
	noteCount, _ := h.DB.Notes.CountDocuments(ctx, bson.M{"IsTrash": false, "IsDeleted": false})
	blogCount, _ := h.DB.Notes.CountDocuments(ctx, bson.M{"IsBlog": true, "IsTrash": false, "IsDeleted": false})
	return c.JSON(types.OkItem(fiber.Map{
		"UserCount": userCount,
		"NoteCount": noteCount,
		"BlogCount": blogCount,
	}))
}

// adminSortFields maps the public sorter keys to stored field names.
var adminSortFields = map[string]string{
	"email":       "Email",
	"username":    "Username",
	"verified":    "Verified",
	"createdtime": "CreatedTime",
}

// parseSorter reads a "field-up"/"field-down" sorter, defaulting to CreatedTime
// descending. Only whitelisted fields are honored.
func parseSorter(sorter string) (string, int) {
	field, dir := "CreatedTime", -1
	parts := strings.Split(sorter, "-")
	if len(parts) == 2 {
		if f, ok := adminSortFields[strings.ToLower(parts[0])]; ok {
			field = f
			if parts[1] == "up" {
				dir = 1
			}
		}
	}
	return field, dir
}

// AdminListUsers returns a paged, sortable, searchable user list.
func (h *Handler) AdminListUsers(c *fiber.Ctx) error {
	ctx := c.Context()
	page, _ := strconv.Atoi(c.Query("page", "1"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.Query("pageSize", strconv.Itoa(adminUserPageSize)))
	if pageSize < 1 || pageSize > 100 {
		pageSize = adminUserPageSize
	}

	query := bson.M{}
	if kw := strings.TrimSpace(c.Query("keywords")); kw != "" {
		rx := primitive.Regex{Pattern: ".*" + regexp.QuoteMeta(kw) + ".*", Options: "i"}
		query["$or"] = []bson.M{{"Email": rx}, {"Username": rx}}
	}

	count, _ := h.DB.Users.CountDocuments(ctx, query)

	field, dir := parseSorter(c.Query("sorter"))
	users := []models.User{}
	cur, err := h.DB.Users.Find(ctx, query, options.Find().
		SetSort(bson.D{{Key: field, Value: dir}}).
		SetSkip(int64((page-1)*pageSize)).
		SetLimit(int64(pageSize)))
	if err == nil {
		_ = cur.All(ctx, &users)
	}
	views := make([]adminUserView, len(users))
	for i, u := range users {
		views[i] = adminUserView{
			UserId:      u.UserId,
			Email:       u.Email,
			Username:    u.UsernameRaw,
			Verified:    u.Verified,
			CreatedTime: u.CreatedTime,
		}
		if views[i].Username == "" {
			views[i].Username = u.Username
		}
	}
	return c.JSON(types.NewPage(page, pageSize, int(count), views))
}

// AdminAddUser creates a user (with default notebooks). Not subject to the
// openRegister switch — it is an explicit admin action.
func (h *Handler) AdminAddUser(c *fiber.Ctx) error {
	email := norm(c.FormValue("email"))
	pwd := c.FormValue("pwd")
	if email == "" || pwd == "" {
		return c.JSON(types.ErrRe("请输入邮箱和密码"))
	}
	if !strings.Contains(email, "@") {
		return c.JSON(types.ErrRe("邮箱格式不正确"))
	}
	if _, err := h.createUser(c.Context(), email, pwd); err != nil {
		return c.JSON(types.ErrRe(err.Error()))
	}
	return c.JSON(types.OkRe())
}

// AdminResetPwd sets a new password for any user.
func (h *Handler) AdminResetPwd(c *fiber.Ctx) error {
	uid, ok := oid.Parse(c.FormValue("userId"))
	if !ok {
		return c.JSON(types.ErrRe("用户不存在"))
	}
	pwd := c.FormValue("pwd")
	if pwd == "" {
		return c.JSON(types.ErrRe("新密码不能为空"))
	}
	hashed, err := auth.GenPwd(pwd)
	if err != nil {
		return c.JSON(types.ErrRe("服务器错误"))
	}
	res, err := h.DB.Users.UpdateOne(c.Context(), bson.M{"_id": uid},
		bson.M{"$set": bson.M{"Pwd": hashed}})
	if err != nil || res.MatchedCount == 0 {
		return c.JSON(types.ErrRe("用户不存在"))
	}
	return c.JSON(types.OkRe())
}

// AdminGetConfigs returns the current global settings (stored value or default).
// The image bed is per-user now and lives under /user/imageBedSettings, not here.
func (h *Handler) AdminGetConfigs(c *fiber.Ctx) error {
	ctx := c.Context()
	return c.JSON(types.OkItem(fiber.Map{
		"openRegister":       h.cfgBool(ctx, cfgOpenRegister, true),
		"uploadImageSize":    h.cfgFloat(ctx, cfgUploadImageSize, cfgDefaultFloat(cfgUploadImageSize)),
		"uploadAttachSize":   h.cfgFloat(ctx, cfgUploadAttachSize, cfgDefaultFloat(cfgUploadAttachSize)),
		"uploadAvatarSize":   h.cfgFloat(ctx, cfgUploadAvatarSize, cfgDefaultFloat(cfgUploadAvatarSize)),
		"allowLocalImageBed": h.cfgBool(ctx, cfgAllowLocalImageBed, true),
	}))
}

// AdminUpdateConfigs upserts whichever settings were submitted. Numeric sizes
// must be > 0; openRegister is normalized to "true"/"false".
func (h *Handler) AdminUpdateConfigs(c *fiber.Ctx) error {
	ctx := c.Context()
	if web.Has(c, cfgOpenRegister) {
		v := strings.ToLower(strings.TrimSpace(c.FormValue(cfgOpenRegister)))
		h.cfgSet(ctx, cfgOpenRegister, strconv.FormatBool(v == "true" || v == "1"))
	}
	if web.Has(c, cfgAllowLocalImageBed) {
		v := strings.ToLower(strings.TrimSpace(c.FormValue(cfgAllowLocalImageBed)))
		h.cfgSet(ctx, cfgAllowLocalImageBed, strconv.FormatBool(v == "true" || v == "1"))
	}
	for _, key := range []string{cfgUploadImageSize, cfgUploadAttachSize, cfgUploadAvatarSize} {
		if !web.Has(c, key) {
			continue
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(c.FormValue(key)), 64)
		if err != nil || f <= 0 {
			return c.JSON(types.ErrRe("上传大小必须为正数"))
		}
		h.cfgSet(ctx, key, strconv.FormatFloat(f, 'f', -1, 64))
	}
	return c.JSON(types.OkRe())
}
