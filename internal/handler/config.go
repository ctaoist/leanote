package handler

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"

	"leanote/internal/imagebed"
	"leanote/internal/models"
)

// Global config keys (stored in the app_configs collection, one doc per key).
// These remain site-wide, admin-only settings. The image bed (where note images
// are stored) is NOT here anymore — it is per-user, stored on the user document
// (see models.User.ImageBed* and the userImageBed* accessors below).
const (
	cfgOpenRegister     = "openRegister"     // "true"/"false": public /doRegister allowed
	cfgUploadImageSize  = "uploadImageSize"  // MB
	cfgUploadAttachSize = "uploadAttachSize" // MB
	cfgUploadAvatarSize = "uploadAvatarSize" // MB
	// cfgAllowLocalImageBed gates whether users may set their image bed to "local"
	// (server local disk). When "false", users must use an S3 bed. Existing local
	// images keep serving; only choosing/saving local going forward is blocked.
	cfgAllowLocalImageBed = "allowLocalImageBed" // "true"/"false"
)

// cfgDefaults holds the fallback value (as a string) for every known key. Reads
// of an unset key return these, matching leanote's default order of magnitude.
// Keys absent here default to "" (the map's zero value).
var cfgDefaults = map[string]string{
	cfgOpenRegister:       "true",
	cfgUploadImageSize:    "2",
	cfgUploadAttachSize:   "5",
	cfgUploadAvatarSize:   "1",
	cfgAllowLocalImageBed: "true",
}

// cfgString reads a string config, falling back to def when unset.
func (h *Handler) cfgString(ctx context.Context, key, def string) string {
	var cfg models.Config
	if err := h.DB.Configs.FindOne(ctx, bson.M{"_id": key}).Decode(&cfg); err != nil {
		return def
	}
	return cfg.ValueStr
}

// cfgBool reads a "true"/"false" config.
func (h *Handler) cfgBool(ctx context.Context, key string, def bool) bool {
	v := h.cfgString(ctx, key, strconv.FormatBool(def))
	return v == "true" || v == "1"
}

// cfgFloat reads a numeric config (e.g. an upload size in MB).
func (h *Handler) cfgFloat(ctx context.Context, key string, def float64) float64 {
	v := h.cfgString(ctx, key, "")
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

// cfgDefaultFloat returns the registered default for a size key as a float.
func cfgDefaultFloat(key string) float64 {
	f, _ := strconv.ParseFloat(cfgDefaults[key], 64)
	return f
}

// cfgSet upserts a string config value (keyed by _id).
func (h *Handler) cfgSet(ctx context.Context, key, value string) {
	_, _ = h.DB.Configs.UpdateOne(ctx,
		bson.M{"_id": key},
		bson.M{"$set": bson.M{"ValueStr": value, "UpdatedTime": time.Now()}},
		options.Update().SetUpsert(true))
}

// overSize reports whether size (bytes) exceeds the configured limit (MB) for
// key. Uploads call this to enforce the admin-set upload limits.
func (h *Handler) overSize(ctx context.Context, key string, size int64) bool {
	limitMB := h.cfgFloat(ctx, key, cfgDefaultFloat(key))
	return size > int64(limitMB*1024*1024)
}

// ----- per-user image bed -----
// The image bed is configured per user and stored on the user document. These
// accessors derive the effective settings from a loaded models.User; handlers
// load the current user once (loadUser) and pass it in.

// userImageBedType returns the user's bed type (local|s3), defaulting to local.
func userImageBedType(u models.User) string {
	if u.ImageBedType == "s3" {
		return "s3"
	}
	return "local"
}

// userImageBeds parses the user's configured beds (JSON array). Returns nil when
// none are configured or the stored value is malformed.
func userImageBeds(u models.User) []imagebed.Bed {
	s := strings.TrimSpace(u.ImageBeds)
	if s == "" || s == "[]" {
		return nil
	}
	var beds []imagebed.Bed
	if err := json.Unmarshal([]byte(s), &beds); err != nil {
		return nil
	}
	return beds
}

// userActiveBed returns the bed used for new uploads (ImageBedActiveId, else the
// first configured bed) and whether one exists.
func userActiveBed(u models.User) (imagebed.Bed, bool) {
	beds := userImageBeds(u)
	if len(beds) == 0 {
		return imagebed.Bed{}, false
	}
	if id := u.ImageBedActiveId; id != "" {
		for _, b := range beds {
			if b.ID == id {
				return b, true
			}
		}
	}
	return beds[0], true
}

// userS3SignMode is the active bed's sign mode (client|server), default client.
func userS3SignMode(u models.User) string {
	if b, ok := userActiveBed(u); ok && b.SignMode == "server" {
		return "server"
	}
	return "client"
}

// userS3Config is the active bed's addressing/signing config (zero when none).
func userS3Config(u models.User) imagebed.S3Config {
	if b, ok := userActiveBed(u); ok {
		return b.S3()
	}
	return imagebed.S3Config{}
}

// userImagePageSize is the user's number of images per page in the picker
// (shared by local and s3 browsing), defaulting to 12 and clamped to 1..100.
func userImagePageSize(u models.User) int {
	n := u.ImagePageSize
	if n < 1 {
		return 12
	}
	if n > 100 {
		return 100
	}
	return n
}
