package user

import (
	"context"

	"github.com/carafie/identity/platform/sqlx"
)

type Store interface {
	GetByEmailOrCreate(ctx context.Context, executor sqlx.Executor, user *User) (*User, error)
}
