package jwt

import (
	"time"

	"github.com/carafie/identity/platform/clock"
	"github.com/carafie/identity/platform/email"
	"github.com/carafie/identity/platform/uuid"
)

type Token struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Email     email.Email
	Kind      Kind
	CreatedAt time.Time
	ExpiresAt time.Time
}

func NewToken(id, userID uuid.UUID, email email.Email, kind Kind, createdAt, expiresAt time.Time) *Token {
	return &Token{
		ID:        id,
		UserID:    userID,
		Email:     email,
		Kind:      kind,
		CreatedAt: clock.Normalize(createdAt),
		ExpiresAt: clock.Normalize(expiresAt),
	}
}
