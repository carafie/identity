package jwt

import (
	"time"

	"github.com/carafie/identity/platform/clock"
	"github.com/carafie/identity/platform/mail"
	"github.com/carafie/identity/platform/uuid"
)

type JWS = string

type Token struct {
	Fields *TokenFields

	// JWS is the JSON Web Signature, commonly referred to as the signed string.
	JWS JWS
}

func newToken(fields *TokenFields, jws JWS) *Token {
	return &Token{
		Fields: fields,
		JWS:    jws,
	}
}

type TokenFields struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Email     mail.Email
	Kind      Kind
	CreatedAt time.Time
	ExpiresAt time.Time
}

func NewTokenFields(userID uuid.UUID, email mail.Email, kind Kind, duration time.Duration) *TokenFields {
	now := clock.Normalize(time.Now())
	return &TokenFields{
		ID:        uuid.New(),
		UserID:    userID,
		Email:     email,
		Kind:      kind,
		CreatedAt: now,
		ExpiresAt: now.Add(duration),
	}
}

func loadTokenFields(id, userID uuid.UUID, email mail.Email, kind Kind, createdAt, expiresAt time.Time) *TokenFields {
	return &TokenFields{
		ID:        id,
		UserID:    userID,
		Email:     email,
		Kind:      kind,
		CreatedAt: clock.Normalize(createdAt),
		ExpiresAt: clock.Normalize(expiresAt),
	}
}
