package slogx

import "log/slog"

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

func RequestID(id string) slog.Attr {
	return slog.String(requestIDKey, id)
}

func OTPID(id string) slog.Attr {
	return slog.String(otpIDKey, id)
}
