package logging

import (
	"context"
	"log/slog"

	"github.com/carafie/identity/internal/uuid"
)

type ctxKey int

const (
	ctxKeyLogger ctxKey = iota
	ctxKeyRequestID
)

func NewContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKeyLogger, logger)
}

func FromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(ctxKeyLogger).(*slog.Logger); ok {
		return logger
	}
	return slog.New(slog.DiscardHandler)
}

func NewRequestIDContext(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID, id)
}

func RequestIDFromContext(ctx context.Context) uuid.UUID {
	if id, ok := ctx.Value(ctxKeyRequestID).(uuid.UUID); ok {
		return id
	}
	return uuid.UUID{}
}

const (
	logKeyError     = "error"
	logKeyRequestID = "request_id"
)

func Error(err error) slog.Attr {
	if err != nil {
		return slog.String(logKeyError, err.Error())
	}
	return slog.Attr{}
}

func RequestID(id uuid.UUID) slog.Attr {
	return slog.String(logKeyRequestID, id.String())
}
