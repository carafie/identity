package databasetest

import (
	"testing"

	"github.com/carafie/identity/internal/database"
)

func TestOpen(t *testing.T) {
	t.Parallel()

	var db *database.DB

	t.Run("open", func(innerT *testing.T) {
		innerDB, close, err := Open(innerT.Context())
		if err != nil {
			innerT.Fatalf("failed to open: %v", err)
		}
		db = innerDB
		t.Cleanup(close)
	})

	t.Run("ping", func(t *testing.T) {
		if err := db.Pool.PingContext(t.Context()); err != nil {
			t.Errorf("failed to ping: %v", err)
		}
	})

	t.Run("query", func(t *testing.T) {
		var result int
		if err := db.Pool.QueryRowContext(t.Context(), "SELECT 1").Scan(&result); err != nil {
			t.Errorf("failed to query: %v", err)
		}
		if result != 1 {
			t.Error("failed to query: unexpected row")
		}
	})
}
