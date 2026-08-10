package store

import (
	"context"

	"github.com/carafie/identity/auth/domain"
	"github.com/carafie/identity/platform/sqlx"
	"github.com/carafie/identity/platform/uuid"
)

type Store interface {
	CreateOTP(ctx context.Context, otp *domain.OTP) error
	ConsumeOTP(ctx context.Context, otpID uuid.UUID) (*domain.OTP, error)

	GetUserByEmailOrCreate(ctx context.Context, user *domain.User) (*domain.User, error)
	DeleteUser(ctx context.Context, userID uuid.UUID) error

	CreateRefreshToken(ctx context.Context, token *domain.RefreshToken) error
	GetRefreshToken(ctx context.Context, refreshTokenID uuid.UUID) (*domain.RefreshToken, error)
	ListRefreshTokens(ctx context.Context, userID uuid.UUID) ([]*domain.RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, userID, refreshTokenID uuid.UUID) error
}

type Provider interface {
	New(executor sqlx.Executor) Store
}
