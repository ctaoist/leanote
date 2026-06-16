// Package auth provides password hashing, cookie sessions, and Fiber middleware.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"

	"leanote/internal/db"
	"leanote/internal/models"
	"leanote/internal/oid"
	"leanote/internal/types"
	"leanote/internal/web"
)

// CookieName is the HttpOnly session cookie. Distinct from Revel's LEANOTE_SESSION.
const CookieName = "leanote_session"

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// CreateSession stores a new session document and returns its token.
func CreateSession(ctx context.Context, database *db.DB, userId oid.OID) (string, error) {
	token := randomToken()
	now := time.Now()
	_, err := database.Sessions.InsertOne(ctx, models.Session{
		Id:          oid.New(),
		Token:       token,
		UserId:      userId,
		CreatedTime: now,
		UpdatedTime: now,
	})
	return token, err
}

// DestroySession deletes the session for the given token (no-op if empty).
func DestroySession(ctx context.Context, database *db.DB, token string) {
	if token == "" {
		return
	}
	_, _ = database.Sessions.DeleteOne(ctx, bson.M{"Token": token})
}

func lookup(ctx context.Context, database *db.DB, token string) (oid.OID, bool) {
	if token == "" {
		return oid.OID{}, false
	}
	var s models.Session
	if err := database.Sessions.FindOne(ctx, bson.M{"Token": token}).Decode(&s); err != nil {
		return oid.OID{}, false
	}
	return s.UserId, !s.UserId.IsZero()
}

// SetSessionCookie writes the session cookie on the response.
func SetSessionCookie(c *fiber.Ctx, token string, ttl time.Duration) {
	c.Cookie(&fiber.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HTTPOnly: true,
		SameSite: "Lax",
		MaxAge:   int(ttl.Seconds()),
	})
}

// ClearSessionCookie expires the session cookie.
func ClearSessionCookie(c *fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HTTPOnly: true,
		MaxAge:   -1,
		Expires:  time.Now().Add(-time.Hour),
	})
}

// Middleware resolves the session cookie to a user id and stores it on the
// request context. It never blocks: unauthenticated requests simply carry no id.
func Middleware(database *db.DB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Cookies(CookieName)
		if uid, ok := lookup(c.Context(), database, token); ok {
			web.SetUserID(c, uid.Hex())
		}
		return c.Next()
	}
}

// RequireAuth rejects unauthenticated requests with 401.
func RequireAuth(c *fiber.Ctx) error {
	if web.UserID(c) == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(types.ErrRe("未登录"))
	}
	return c.Next()
}
