package mailer

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/carafie/identity/auth/domain"
	"github.com/carafie/identity/internal/logging"
)

type Log struct {
	params Params
}

var _ Mailer = &Log{}

func NewLog(params Params) *Log {
	return &Log{params: params}
}

func (l *Log) SendOTPRequest(ctx context.Context, otp *domain.OTP) error {
	logger := logging.FromContext(ctx)
	logger.InfoContext(ctx, "send otp request email",
		slog.String("from", l.params.FromAddress),
		slog.String("to", string(otp.Email)),
		slog.String("subject", l.params.SendOTPRequestSubject),
		slog.String("content", fmt.Sprintf(l.params.SendOTPRequestContent, string(otp.Code))),
	)
	return nil
}
