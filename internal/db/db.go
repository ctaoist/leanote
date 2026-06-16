// Package db wires the MongoDB client and exposes the collections the app uses.
package db

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type DB struct {
	Client   *mongo.Client
	Database *mongo.Database

	Notebooks            *mongo.Collection
	Notes                *mongo.Collection
	NoteContents         *mongo.Collection
	NoteContentHistories *mongo.Collection
	Users                *mongo.Collection
	Tags                 *mongo.Collection
	Files                *mongo.Collection
	Albums               *mongo.Collection
	Attachs              *mongo.Collection
	Sessions             *mongo.Collection // app_sessions (new, not Revel's)
	Configs              *mongo.Collection // app_configs (new, not Revel's `configs`)
	UserBlogs            *mongo.Collection // user_blogs (existing leanote, _id=userId)
	Themes               *mongo.Collection // themes (existing leanote, file-based)
	BlogSingles          *mongo.Collection // blog_singles (existing leanote single-pages)
}

// Connect dials MongoDB and verifies the connection with a ping.
func Connect(uri, dbname string) (*DB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}
	d := client.Database(dbname)
	db := &DB{
		Client:               client,
		Database:             d,
		Notebooks:            d.Collection("notebooks"),
		Notes:                d.Collection("notes"),
		NoteContents:         d.Collection("note_contents"),
		NoteContentHistories: d.Collection("note_content_histories"),
		Users:                d.Collection("users"),
		Tags:                 d.Collection("tags"),
		Files:                d.Collection("files"),
		Albums:               d.Collection("albums"),
		Attachs:              d.Collection("attachs"),
		Sessions:             d.Collection("app_sessions"),
		Configs:              d.Collection("app_configs"),
		UserBlogs:            d.Collection("user_blogs"),
		Themes:               d.Collection("themes"),
		BlogSingles:          d.Collection("blog_singles"),
	}
	return db, nil
}

// EnsureIndexes creates the session TTL index plus the blog host-routing lookup
// indexes. Best-effort: errors are returned but non-fatal to the caller's
// discretion.
func (db *DB) EnsureIndexes(ttl time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := db.Sessions.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "Token", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "UpdatedTime", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(int32(ttl.Seconds()))},
	}); err != nil {
		return err
	}
	// Sparse (not unique — uniqueness is enforced at save time to avoid failing on
	// legacy duplicates) indexes so host routing's per-request SubDomain/Domain
	// lookups stay cheap.
	_, err := db.UserBlogs.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "SubDomain", Value: 1}}, Options: options.Index().SetSparse(true)},
		{Keys: bson.D{{Key: "Domain", Value: 1}}, Options: options.Index().SetSparse(true)},
	})
	return err
}

func (db *DB) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = db.Client.Disconnect(ctx)
}
