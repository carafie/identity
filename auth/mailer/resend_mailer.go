package mailer

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/carafie/identity/auth/domain"
	"github.com/resend/resend-go/v3"
)

type Resend struct {
	client *resend.Client
	params Params
}

var _ Mailer = &Resend{}

func NewResend(apiKey string, timeout time.Duration, params Params) *Resend {
	client := resend.NewCustomClient(
		&http.Client{Timeout: timeout},
		apiKey,
	)
	return &Resend{
		client: client,
		params: params,
	}
}

func (r *Resend) SendOTPRequest(ctx context.Context, otp *domain.OTP) error {
	if otp == nil {
		return nil
	}
	params := &resend.SendEmailRequest{
		From:    r.params.FromAddress,
		To:      []string{string(otp.Email)},
		Subject: r.params.SendOTPRequestSubject,
		Text:    fmt.Sprintf(r.params.SendOTPRequestContent, string(otp.Code)),
	}
	_, err := r.client.Emails.SendWithContext(ctx, params)
	return err
}
