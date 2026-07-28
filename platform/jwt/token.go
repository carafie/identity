package jwt

import (
	"time"

	"github.com/carafie/identity/platform/clock"
	"github.com/carafie/identity/platform/email"
	"github.com/carafie/identity/platform/uuid"
)

type SignedToken = string

type TokenFields struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Email     email.Email
	Kind      Kind
	CreatedAt time.Time
	ExpiresAt time.Time
}

func NewTokenFields(userID uuid.UUID, em email.Email, kind Kind, duration time.Duration) *TokenFields {
	now := clock.Normalize(time.Now())
	return &TokenFields{
		ID:        uuid.New(),
		UserID:    userID,
		Email:     em,
		Kind:      kind,
		CreatedAt: now,
		ExpiresAt: now.Add(duration),
	}
}

func loadTokenFields(id, userID uuid.UUID, em email.Email, kind Kind, createdAt, expiresAt time.Time) *TokenFields {
	return &TokenFields{
		ID:        id,
		UserID:    userID,
		Email:     em,
		Kind:      kind,
		CreatedAt: clock.Normalize(createdAt),
		ExpiresAt: clock.Normalize(expiresAt),
	}
}
