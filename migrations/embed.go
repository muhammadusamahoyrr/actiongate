// Package migrations embeds the goose SQL migrations so binaries can
// self-migrate without the goose CLI installed (used by `actiongate up`).
// The CLI path (`make migrate`) reads the same files from disk.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
