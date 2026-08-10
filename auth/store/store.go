package store

import (
	"context"

	"github.com/carafie/identity/auth/domain"
	"github.com/carafie/identity/platform/sqlx"
	"github.com/carafie/identity/platform/uuid"
)

type Store interface {
	CreateOTP(ctx context.Context, executor sqlx.Executor, otp *domain.OTP) error
	ConsumeOTP(ctx context.Context, executor sqlx.Executor, otpID uuid.UUID) (*domain.OTP, error)

	GetUserByEmailOrCreate(ctx context.Context, executor sqlx.Executor, user *domain.User) (*domain.User, error)
	DeleteUser(ctx context.Context, executor sqlx.Executor, userID uuid.UUID) error

	CreateRefreshToken(ctx context.Context, executor sqlx.Executor, token *domain.RefreshToken) error
	GetRefreshToken(ctx context.Context, executor sqlx.Executor, refreshTokenID uuid.UUID) (
		*domain.RefreshToken, error,
	)
	ListRefreshTokens(ctx context.Context, executor sqlx.Executor, userID uuid.UUID) ([]*domain.RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, executor sqlx.Executor, userID, refreshTokenID uuid.UUID) error
}
