package mailer

import (
	"context"

	"github.com/carafie/identity/auth/domain"
)

type Mailer interface {
	SendOTPRequest(ctx context.Context, otp *domain.OTP) error
}

type Params struct {
	FromAddress string

	SendOTPRequestSubject string

	// SendOTPRequestContent must contain a single %s format specifier
	// where the OTP code will be inserted via fmt.Sprintf.
	SendOTPRequestContent string
}
