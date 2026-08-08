package mailer

import (
	"context"

	"github.com/carafie/identity/auth/domain"
)

type Mailer interface {
	SendOTPRequest(ctx context.Context, otp *domain.OTP) error
}
