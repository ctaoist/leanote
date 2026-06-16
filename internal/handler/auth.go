package handler

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"leanote/internal/auth"
	"leanote/internal/models"
	"leanote/internal/oid"
	"leanote/internal/types"
)

func norm(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// DoLogin authenticates email-or-username + password, opening a cookie session.
func (h *Handler) DoLogin(c *fiber.Ctx) error {
	name := norm(c.FormValue("email"))
	pwd := c.FormValue("pwd")
	if name == "" || pwd == "" {
		return c.JSON(types.Re{Ok: false, Item: false, Msg: "请输入用户名和密码"})
	}
	user, ok := h.findUserByName(c.Context(), name)
	if !ok || !auth.ComparePwd(pwd, user.Pwd) {
		return c.JSON(types.Re{Ok: false, Item: false, Msg: "用户名或密码错误"})
	}
	token, err := auth.CreateSession(c.Context(), h.DB, user.UserId)
	if err != nil {
		return c.JSON(types.ErrRe("服务器错误"))
	}
	auth.SetSessionCookie(c, token, h.Cfg.SessionTTL)
	return c.JSON(types.OkRe())
}

// Logout destroys the session and clears the cookie.
func (h *Handler) Logout(c *fiber.Ctx) error {
	token := c.Cookies(auth.CookieName)
	auth.DestroySession(c.Context(), h.DB, token)
	auth.ClearSessionCookie(c)
	return c.JSON(types.OkRe())
}

// DoRegister creates a user with the default three notebooks (life/study/work).
func (h *Handler) DoRegister(c *fiber.Ctx) error {
	if !h.cfgBool(c.Context(), cfgOpenRegister, true) {
		return c.JSON(types.ErrRe("管理员已关闭注册"))
	}
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

// createUser inserts a new user plus the default three notebooks. Shared by the
// public /doRegister flow and the admin /admin/addUser endpoint. The returned
// error message is user-facing (Chinese).
func (h *Handler) createUser(ctx context.Context, email, pwd string) (models.User, error) {
	email = norm(email)
	if _, exists := h.findUserByName(ctx, email); exists {
		return models.User{}, errors.New("该邮箱已注册")
	}
	hashed, err := auth.GenPwd(pwd)
	if err != nil {
		return models.User{}, errors.New("服务器错误")
	}
	now := time.Now()
	user := models.User{
		UserId:      oid.New(),
		Email:       email,
		Username:    email,
		UsernameRaw: email,
		Pwd:         hashed,
		CreatedTime: now,
	}
	if _, err := h.DB.Users.InsertOne(ctx, user); err != nil {
		return models.User{}, errors.New("注册失败")
	}
	for _, title := range []string{"life", "study", "work"} {
		nbID := oid.New()
		_, _ = h.DB.Notebooks.InsertOne(ctx, models.Notebook{
			NotebookId:  nbID,
			UserId:      user.UserId,
			Title:       title,
			UrlTitle:    h.uniqueNotebookUrlTitle(ctx, user.UserId, nbID, title),
			Seq:         -1,
			CreatedTime: now,
			UpdatedTime: now,
		})
	}
	return user, nil
}

// DoFindPassword: email delivery is not configured in this environment, so this
// logs the request and reports that honestly rather than silently succeeding.
func (h *Handler) DoFindPassword(c *fiber.Ctx) error {
	email := norm(c.FormValue("email"))
	if _, ok := h.findUserByName(c.Context(), email); !ok {
		return c.JSON(types.ErrRe("用户不存在"))
	}
	log.Printf("find-password requested for %s (email delivery not configured)", email)
	return c.JSON(types.ErrRe("当前环境未配置邮件服务，无法发送找回邮件"))
}

func (h *Handler) FindPasswordUpdate(c *fiber.Ctx) error {
	return c.JSON(types.ErrRe("当前环境未配置邮件服务"))
}
