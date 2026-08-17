package domain

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/carafie/identity/internal/clock"
	"github.com/carafie/identity/internal/mail"
	"github.com/carafie/identity/internal/uuid"
)

var (
	ErrCodeInvalid    = errors.New("code is invalid")
	ErrCodeExpired    = errors.New("code is expired")
	ErrCodeMismatched = errors.New("code is mismatched")
)

type OTP struct {
	ID        uuid.UUID
	Email     mail.Email
	Code      Code
	Attempts  int
	CreatedAt time.Time
	ExpiresAt time.Time
}

func NewOTP(email mail.Email, duration time.Duration) *OTP {
	now := clock.Normalize(time.Now())
	return &OTP{
		ID:        uuid.New(),
		Email:     email,
		Code:      NewCode(),
		Attempts:  0,
		CreatedAt: now,
		ExpiresAt: now.Add(duration),
	}
}

func LoadOTP(id uuid.UUID, email mail.Email, code Code, attempts int, createdAt, expiresAt time.Time) *OTP {
	return &OTP{
		ID:        id,
		Email:     email,
		Code:      code,
		Attempts:  attempts,
		CreatedAt: clock.Normalize(createdAt),
		ExpiresAt: clock.Normalize(expiresAt),
	}
}

func (otp *OTP) Validate(code Code, maxAttempts int) error {
	if otp == nil || clock.InPast(otp.ExpiresAt) {
		return ErrCodeExpired
	}
	if otp.Attempts >= maxAttempts {
		return ErrCodeExpired
	}
	if otp.Code != code {
		return ErrCodeMismatched
	}
	return nil
}

type Code string

func NewCode() Code {
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		// This should never happen.
		panic(fmt.Errorf("domain.NewCode: failed to generate random code: %w", err))
	}
	return Code(fmt.Sprintf("%06d", n.Int64()))
}

func ParseCode(code string) (Code, error) {
	if len(code) != 6 {
		return "", ErrCodeInvalid
	}
	for _, char := range code {
		if char < '0' || char > '9' {
			return "", ErrCodeInvalid
		}
	}
	return Code(code), nil
}
