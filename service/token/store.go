package token

import (
	"context"

	"github.com/carafie/identity/platform/sqlx"
)

type Store interface {
	CreateRefresh(ctx context.Context, executor sqlx.Executor, token Refresh) error
}
