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
	client                *resend.Client
	fromAddress           string
	sendOTPRequestSubject string
	sendOTPRequestContent string
}

var _ Mailer = &Resend{}

func NewResend(apiKey string, timeout time.Duration, params Params) *Resend {
	client := resend.NewCustomClient(
		&http.Client{Timeout: timeout},
		apiKey,
	)
	return &Resend{
		client:                client,
		fromAddress:           params.FromAddress,
		sendOTPRequestSubject: params.SendOTPRequestSubject,
		sendOTPRequestContent: params.SendOTPRequestContent,
	}
}

func (r *Resend) SendOTPRequest(ctx context.Context, otp *domain.OTP) error {
	if otp == nil {
		return nil
	}
	params := &resend.SendEmailRequest{
		From:    r.fromAddress,
		To:      []string{string(otp.Email)},
		Subject: r.sendOTPRequestSubject,
		Text:    fmt.Sprintf(r.sendOTPRequestContent, string(otp.Code)),
	}
	_, err := r.client.Emails.SendWithContext(ctx, params)
	return err
}
