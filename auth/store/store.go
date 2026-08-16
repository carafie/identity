package store

import (
	"context"

	"github.com/carafie/identity/auth/domain"
	"github.com/carafie/identity/internal/database"
	"github.com/carafie/identity/internal/uuid"
)

type Factory interface {
	New(executor database.Executor) Store
}

type Store interface {
	CreateOTP(ctx context.Context, otp *domain.OTP) error
	ConsumeOTP(ctx context.Context, otpID uuid.UUID) (*domain.OTP, error)
	DeleteOTP(ctx context.Context, otpID uuid.UUID) error

	GetUserByEmailOrCreate(ctx context.Context, user *domain.User) (*domain.User, error)
	DeleteUser(ctx context.Context, userID uuid.UUID) error

	CreateRefreshToken(ctx context.Context, token *domain.RefreshToken) error
	GetRefreshToken(ctx context.Context, userID, refreshTokenID uuid.UUID) (*domain.RefreshToken, error)
	ListRefreshTokens(ctx context.Context, userID uuid.UUID) ([]*domain.RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, userID, refreshTokenID uuid.UUID) error
}
