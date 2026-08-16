package identity

import "embed"

const MigrationsPath = "migrations"

//go:embed migrations
var FS embed.FS
