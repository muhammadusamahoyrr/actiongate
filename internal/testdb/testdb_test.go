package testdb

import (
	"testing"

	"github.com/muhammadusamahoyrr/actiongate/migrations"
	"github.com/pressly/goose/v3"
)

func TestEmbeddedMigrationsAreDiscoverable(t *testing.T) {
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("goose dialect: %v", err)
	}
	goose.SetBaseFS(migrations.FS)
	t.Cleanup(func() { goose.SetBaseFS(nil) })

	migs, err := goose.CollectMigrations(".", 0, goose.MaxVersion)
	if err != nil {
		t.Fatalf("collect migrations: %v", err)
	}
	if len(migs) == 0 {
		t.Fatal("expected embedded SQL migrations, found none")
	}
}
