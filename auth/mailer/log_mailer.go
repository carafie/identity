package mailer

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/carafie/identity/auth/domain"
)

type Log struct {
	logger *slog.Logger
	params Params
}

var _ Mailer = &Log{}

func NewLog(logger *slog.Logger, params Params) *Log {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Log{
		logger: logger,
		params: params,
	}
}

func (l *Log) SendOTPRequest(ctx context.Context, otp *domain.OTP) error {
	l.logger.InfoContext(ctx, "",
		slog.String("from", l.params.FromAddress),
		slog.String("to", string(otp.Email)),
		slog.String("subject", l.params.SendOTPRequestSubject),
		slog.String("content", fmt.Sprintf(l.params.SendOTPRequestContent, string(otp.Code))),
	)
	return nil
}
