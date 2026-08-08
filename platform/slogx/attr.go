package slogx

import (
	"log/slog"

	"github.com/carafie/identity/platform/uuid"
)

const (
	errorKey     = "error"
	requestIDKey = "request_id"
	otpIDKey     = "otp_id"
)

func Error(err error) slog.Attr {
	if err != nil {
		return slog.String(errorKey, err.Error())
	}
	return slog.Attr{}
}

func RequestID(id uuid.UUID) slog.Attr {
	return slog.String(requestIDKey, id.String())
}

func OTPID(id uuid.UUID) slog.Attr {
	return slog.String(otpIDKey, id.String())
}
