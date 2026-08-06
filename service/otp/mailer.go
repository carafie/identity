package otp

import "context"

type Mailer interface {
	SendRequest(ctx context.Context, otp *OTP) error
}
