package token

import (
	"time"

	"github.com/carafie/identity/platform/clock"
	"github.com/carafie/identity/platform/jwt"
	"github.com/carafie/identity/platform/uuid"
)

type Access = jwt.AccessToken

type Refresh struct {
	Token     jwt.RefreshToken
	ID        uuid.UUID
	UserID    uuid.UUID
	CreatedAt time.Time
	ExpiresAt time.Time
}

func NewRefresh(token jwt.RefreshToken, id, userID uuid.UUID, createdAt, expiresAt time.Time) Refresh {
	return Refresh{
		Token:     token,
		ID:        id,
		UserID:    userID,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}
}

func (r Refresh) SecondsLeft() int {
	return int(r.ExpiresAt.Sub(clock.Normalize(time.Now())).Seconds())
}
