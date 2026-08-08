package handler

import (
	"net/http"

	"github.com/carafie/identity/auth/domain"
	"github.com/carafie/identity/platform/clock"
)

func SetRefreshCookie(w http.ResponseWriter, token *domain.RefreshToken) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    token.JWS,
		Path:     "/auth/token/refresh",
		MaxAge:   clock.SecondsUntil(token.Fields.ExpiresAt),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
