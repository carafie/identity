package handler

import (
	"log/slog"
	"net/http"

	"github.com/carafie/identity/internal/logging"
	"github.com/google/uuid"
)

func WithRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(
			w,
			r.WithContext(logging.NewRequestIDContext(r.Context(), uuid.New())),
		)
	})
}

func WithLogger(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := logging.RequestIDFromContext(r.Context())
		l := logger.With(logging.RequestID(requestID))
		next.ServeHTTP(
			w,
			r.WithContext(logging.NewContext(r.Context(), l)),
		)
	})
}
