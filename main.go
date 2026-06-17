package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"runtime/debug"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

	"leanote/config"
	"leanote/internal/db"
	"leanote/internal/router"
)

// version is the build version. Injected at build time via
//
//	go build -ldflags "-X main.version=v1.2.3"
//
// When left at the default, versionString falls back to the VCS revision
// the Go toolchain embeds for a `go build` from a git checkout.
var version = "dev"

// versionString returns the human-readable build version, enriching the
// default "dev" with the embedded VCS revision when available.
func versionString() string {
	if version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if rev == "" {
		return version
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return "dev+" + rev + dirty
}

func main() {
	configPath := flag.String("config", "", "path to YAML config file (overrides auto-discovery of config.yaml)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.BoolVar(showVersion, "v", false, "print the version and exit (shorthand)")
	flag.Parse()

	if *showVersion || flag.Arg(0) == "version" {
		fmt.Println(versionString())
		return
	}

	cfg := config.LoadFrom(*configPath)

	database, err := db.Connect(cfg.MongoURI, cfg.MongoDB)
	if err != nil {
		log.Fatalf("mongo connect: %v", err)
	}
	defer database.Close()
	if err := database.EnsureIndexes(cfg.SessionTTL); err != nil {
		log.Printf("warn: ensure indexes: %v", err)
	}
	log.Printf("connected to mongo db=%s", cfg.MongoDB)

	app := fiber.New(fiber.Config{
		BodyLimit: 64 * 1024 * 1024, // 64MB, allow image/attachment uploads
	})
	app.Use(recover.New())
	app.Use(logger.New(logger.Config{Format: "${time} ${status} ${method} ${path} ${latency}\n"}))

	app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true})
	})

	router.Register(app, cfg, database)

	// Serve the embedded SPA for anything not matched by an API route above.
	// Registered last so API routes win; NotFoundFile makes client-side routes
	// (/note, /admin, /login, …) and deep links resolve to index.html.
	app.Use("/", filesystem.New(filesystem.Config{
		Root:         http.FS(webuiFS()),
		Index:        "index.html",
		NotFoundFile: "index.html",
	}))

	log.Printf("leanote-server %s listening on :%s", versionString(), cfg.Port)
	if err := app.Listen(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}
