package config

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds runtime configuration. Values are resolved with increasing
// priority: built-in defaults < YAML config file < environment variables.
type Config struct {
	MongoURI      string
	MongoDB       string
	Port          string
	FileRoot      string
	SessionSecret string
	SessionTTL    time.Duration
	AdminUsername string
	// AppHost is the main application's hostname (e.g. "leanote.example.com").
	// When set, requests to it short-circuit host-based blog routing with no DB
	// lookup. Optional — leave empty in dev.
	AppHost string
	// BlogBaseDomain enables subdomain blogs: a request to "<sub>.<BlogBaseDomain>"
	// resolves to the user whose blog SubDomain == "<sub>". Optional — leave empty
	// to disable subdomain routing (custom domains still work via UserBlog.Domain).
	BlogBaseDomain string
}

// fileConfig is the YAML schema. All fields are strings and optional — an empty
// (omitted) field falls through to the env var, then the default. Kept flat to
// match the single-file infrastructure config (the image-bed/app settings live
// in MongoDB's app_configs, not here).
type fileConfig struct {
	MongoURI      string `yaml:"mongo_uri"`
	MongoDB       string `yaml:"mongo_db"`
	Port          string `yaml:"port"`
	FileRoot      string `yaml:"file_root"`
	SessionSecret string `yaml:"session_secret"`
	SessionTTL    string `yaml:"session_ttl"`
	AdminUsername string `yaml:"admin_username"`
	AppHost        string `yaml:"app_host"`
	BlogBaseDomain string `yaml:"blog_base_domain"`
}

// Load resolves config via auto-discovery: the CONFIG_FILE env var, else
// config.yaml / config.yml in the working dir or next to the binary.
func Load() Config { return LoadFrom("") }

// LoadFrom is Load with an explicit config path (e.g. a -config flag) taking
// priority for locating the file. An explicitly-named file that can't be read
// or parsed is fatal; auto-discovery misses fall back to defaults+env silently.
func LoadFrom(explicitPath string) Config {
	fc := loadFile(explicitPath)
	// pick: env var (if set) > file value (if set) > default.
	pick := func(envKey, fileVal, def string) string {
		if v := os.Getenv(envKey); v != "" {
			return v
		}
		if fileVal != "" {
			return fileVal
		}
		return def
	}
	ttlStr := pick("SESSION_TTL", fc.SessionTTL, "72h")
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		log.Printf("config: invalid session_ttl %q, using 72h", ttlStr)
		ttl = 72 * time.Hour
	}
	return Config{
		MongoURI:      pick("MONGO_URI", fc.MongoURI, "mongodb://user:password@127.0.0.1:27017/leanote?authSource=admin"),
		MongoDB:       pick("MONGO_DB", fc.MongoDB, "leanote"),
		Port:          pick("PORT", fc.Port, "9016"),
		FileRoot:      pick("FILE_ROOT", fc.FileRoot, "/leanote"),
		SessionSecret: pick("SESSION_SECRET", fc.SessionSecret, "dev-insecure-secret-change-me"),
		SessionTTL:    ttl,
		AdminUsername: pick("ADMIN_USERNAME", fc.AdminUsername, "user"),
		AppHost:        pick("APP_HOST", fc.AppHost, ""),
		BlogBaseDomain: pick("BLOG_BASE_DOMAIN", fc.BlogBaseDomain, ""),
	}
}

// loadFile finds and parses the YAML config file. Returns a zero fileConfig when
// no file is found via auto-discovery.
func loadFile(explicitPath string) fileConfig {
	path, explicit := resolvePath(explicitPath)
	if path == "" {
		return fileConfig{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if explicit {
			log.Fatalf("config: cannot read %s: %v", path, err)
		}
		return fileConfig{}
	}
	var fc fileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		log.Fatalf("config: invalid YAML in %s: %v", path, err)
	}
	log.Printf("config: loaded %s", path)
	return fc
}

// resolvePath picks the config file path: explicit (flag) > CONFIG_FILE env >
// the first existing config.yaml / config.yml in the working dir, then next to
// the executable. The bool reports whether the path was explicitly requested
// (so a missing explicit file is an error, a missing discovered one is not).
func resolvePath(explicitPath string) (string, bool) {
	if explicitPath != "" {
		return explicitPath, true
	}
	if v := os.Getenv("CONFIG_FILE"); v != "" {
		return v, true
	}
	var dirs []string
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, wd)
	}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	for _, d := range dirs {
		for _, name := range []string{"config.yaml", "config.yml"} {
			p := filepath.Join(d, name)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p, false
			}
		}
	}
	return "", false
}
