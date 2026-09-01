package handler

import (
	"log/slog"
	"net/http"
	"uuid"

	"github.com/carafie/identity/internal/logging"
)

func WithRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(
			w,
			r.WithContext(logging.NewRequestIDContext(r.Context(), uuid.NewV7())),
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
