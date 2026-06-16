package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

	"leanote/config"
	"leanote/internal/db"
	"leanote/internal/router"
)

func main() {
	configPath := flag.String("config", "", "path to YAML config file (overrides auto-discovery of config.yaml)")
	flag.Parse()
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

	log.Printf("leanote-server listening on :%s", cfg.Port)
	if err := app.Listen(":" + cfg.Port); err != nil {
		log.Fatal(err)
	}
}
