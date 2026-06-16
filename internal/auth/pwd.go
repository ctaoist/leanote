package auth

import (
	"crypto/md5"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

// Md5 returns the hex md5 of s (legacy password scheme).
func Md5(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ComparePwd mirrors the legacy leanote app/lea.ComparePwd: a 32-char stored
// value is a legacy md5 hash; anything else is a bcrypt hash. This lets existing
// users (e.g. ctaoist) log in unchanged.
func ComparePwd(raw, stored string) bool {
	if len(stored) == 32 {
		return Md5(raw) == stored
	}
	return bcrypt.CompareHashAndPassword([]byte(stored), []byte(raw)) == nil
}

// GenPwd hashes a new password with bcrypt (cost 10), matching the legacy app.
func GenPwd(raw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(raw), 10)
	if err != nil {
		return "", err
	}
	return string(h), nil
}
