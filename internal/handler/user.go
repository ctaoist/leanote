package handler

import (
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"

	"leanote/internal/auth"
	"leanote/internal/models"
	"leanote/internal/types"
	"leanote/internal/web"
)

// UserInfo returns the authenticated user (replaces the old /note HTML
// UserInfo-injection bootstrap with a clean JSON endpoint).
func (h *Handler) UserInfo(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	if uid.IsZero() {
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrRe("未登录"))
	}
	var u models.User
	if err := h.DB.Users.FindOne(c.Context(), bson.M{"_id": uid}).Decode(&u); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrRe("未登录"))
	}
	u.IsAdmin = u.Username == h.Cfg.AdminUsername
	return c.JSON(u)
}

// UpdateUsername changes the username (must be unique, case-insensitive).
func (h *Handler) UpdateUsername(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	raw := strings.TrimSpace(c.FormValue("username"))
	if raw == "" || len(raw) > 30 || strings.ContainsAny(raw, " \t\n") {
		return c.JSON(types.ErrRe("用户名不合法"))
	}
	lower := strings.ToLower(raw)
	taken, _ := h.DB.Users.CountDocuments(c.Context(),
		bson.M{"Username": lower, "_id": bson.M{"$ne": uid}})
	if taken > 0 {
		return c.JSON(types.ErrRe("用户名已存在"))
	}
	if _, err := h.DB.Users.UpdateOne(c.Context(), bson.M{"_id": uid},
		bson.M{"$set": bson.M{"Username": lower, "UsernameRaw": raw}}); err != nil {
		return c.JSON(types.ErrRe("更新失败"))
	}
	return c.JSON(types.OkRe())
}

// UpdatePwd verifies the old password then sets a new bcrypt hash.
func (h *Handler) UpdatePwd(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	oldPwd := c.FormValue("oldPwd")
	pwd := c.FormValue("pwd")
	if pwd == "" {
		return c.JSON(types.ErrRe("新密码不能为空"))
	}
	var u models.User
	if err := h.DB.Users.FindOne(c.Context(), bson.M{"_id": uid}).Decode(&u); err != nil {
		return c.JSON(types.ErrRe("用户不存在"))
	}
	if !auth.ComparePwd(oldPwd, u.Pwd) {
		return c.JSON(types.ErrRe("旧密码错误"))
	}
	hashed, err := auth.GenPwd(pwd)
	if err != nil {
		return c.JSON(types.ErrRe("服务器错误"))
	}
	if _, err := h.DB.Users.UpdateOne(c.Context(), bson.M{"_id": uid},
		bson.M{"$set": bson.M{"Pwd": hashed}}); err != nil {
		return c.JSON(types.ErrRe("更新失败"))
	}
	return c.JSON(types.OkRe())
}

// UpdateTheme sets the user's theme.
func (h *Handler) UpdateTheme(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	_, _ = h.DB.Users.UpdateOne(c.Context(), bson.M{"_id": uid},
		bson.M{"$set": bson.M{"Theme": c.FormValue("theme")}})
	return c.JSON(types.OkRe())
}

// UpdateColumnWidth persists the panel widths that were sent.
func (h *Handler) UpdateColumnWidth(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	set := bson.M{}
	put := func(form, field string) {
		if web.Has(c, form) {
			if n, err := strconv.Atoi(strings.TrimSpace(c.FormValue(form))); err == nil {
				set[field] = n
			}
		}
	}
	put("notebookWidth", "NotebookWidth")
	put("noteListWidth", "NoteListWidth")
	put("mdEditorWidth", "MdEditorWidth")
	if len(set) > 0 {
		_, _ = h.DB.Users.UpdateOne(c.Context(), bson.M{"_id": uid}, bson.M{"$set": set})
	}
	return c.JSON(types.OkRe())
}

// UpdateLeftIsMin persists the left-panel collapsed flag.
func (h *Handler) UpdateLeftIsMin(c *fiber.Ctx) error {
	uid := web.UserOID(c)
	_, _ = h.DB.Users.UpdateOne(c.Context(), bson.M{"_id": uid},
		bson.M{"$set": bson.M{"LeftIsMin": formBool(c, "leftIsMin")}})
	return c.JSON(types.OkRe())
}

// ReSendActiveEmail: email delivery is not configured in this environment.
func (h *Handler) ReSendActiveEmail(c *fiber.Ctx) error {
	return c.JSON(types.ErrRe("当前环境未配置邮件服务"))
}
