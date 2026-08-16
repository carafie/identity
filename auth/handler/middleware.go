package handler

import (
	"net/http"

	"github.com/carafie/identity/internal/requestid"
	"github.com/google/uuid"
)

func WithRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(
			w,
			r.WithContext(requestid.ToContext(r.Context(), uuid.New())),
		)
	})
}
