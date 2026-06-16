// Package web holds small Fiber request helpers shared across handlers.
package web

import (
	"github.com/gofiber/fiber/v2"

	"leanote/internal/oid"
)

const userIDKey = "userId"

// SetUserID stores the authenticated user's hex id on the request context.
func SetUserID(c *fiber.Ctx, id string) { c.Locals(userIDKey, id) }

// UserID returns the authenticated user's hex id, or "" if unauthenticated.
func UserID(c *fiber.Ctx) string {
	if v, ok := c.Locals(userIDKey).(string); ok {
		return v
	}
	return ""
}

// UserOID returns the authenticated user's id as an OID (zero if unauthenticated).
func UserOID(c *fiber.Ctx) oid.OID {
	o, _ := oid.FromHex(UserID(c))
	return o
}

// FormArray reads repeated form/query values for name, accepting both the
// Revel-style `name[]` and the bare `name` (the frontend encodes arrays as
// `noteIds[]=a&noteIds[]=b`).
func FormArray(c *fiber.Ctx, name string) []string {
	out := []string{}
	collect := func(visit func(func(k, v []byte))) {
		visit(func(k, v []byte) {
			ks := string(k)
			if ks == name+"[]" || ks == name {
				out = append(out, string(v))
			}
		})
	}
	collect(c.Request().PostArgs().VisitAll)
	collect(c.Request().URI().QueryArgs().VisitAll)
	return out
}

// Has reports whether a field was present in the urlencoded POST body. Mirrors
// Revel's c.Has(field), used for partial note updates.
func Has(c *fiber.Ctx, name string) bool {
	return c.Request().PostArgs().Has(name)
}
