package otp

import (
	"context"

	"github.com/carafie/identity/platform/sqlx"
	"github.com/carafie/identity/platform/uuid"
)

type Store interface {
	Create(ctx context.Context, executor sqlx.Executor, otp *OTP) error
	Consume(ctx context.Context, executor sqlx.Executor, id uuid.UUID) (*OTP, error)
}
