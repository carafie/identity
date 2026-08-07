package otp

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/carafie/identity/platform/clock"
	"github.com/carafie/identity/platform/mail"
	"github.com/carafie/identity/platform/uuid"
)

var ErrCodeInvalid = errors.New("code is invalid")

type OTP struct {
	ID        uuid.UUID
	Email     mail.Email
	Code      Code
	Attempts  int
	CreatedAt time.Time
	ExpiresAt time.Time
}

func New(email mail.Email, duration time.Duration) *OTP {
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

func (otp *OTP) Validate(code Code, maxAttempts int) error {
	if otp == nil || otp.Expired() {
		return ErrCodeExpired
	}
	if otp.Attempts >= maxAttempts {
		return ErrCodeExpired
	}
	if otp.Code != code {
		return ErrCodeMismatch
	}
	return nil
}

func (otp *OTP) Expired() bool {
	return otp.ExpiresAt.Before(clock.Normalize(time.Now()))
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
