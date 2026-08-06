package otp

import (
	"context"

	"github.com/carafie/identity/platform/sqlx"
)

type Store interface {
	Create(ctx context.Context, executor sqlx.Executor, otp *OTP) error
}
