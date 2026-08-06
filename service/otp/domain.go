package otp

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/carafie/identity/platform/clock"
	"github.com/carafie/identity/platform/email"
	"github.com/carafie/identity/platform/uuid"
)

type OTP struct {
	ID        uuid.UUID
	Email     email.Email
	Code      Code
	Attempts  int
	CreatedAt time.Time
	ExpiresAt time.Time
}

func New(em email.Email, duration time.Duration) *OTP {
	now := clock.Normalize(time.Now())
	return &OTP{
		ID:        uuid.New(),
		Email:     em,
		Code:      NewCode(),
		Attempts:  0,
		CreatedAt: now,
		ExpiresAt: now.Add(duration),
	}
}

type Code string

func NewCode() Code {
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(fmt.Errorf("failed to generate random code: %w", err))
	}
	return Code(fmt.Sprintf("%06d", n.Int64()))
}
