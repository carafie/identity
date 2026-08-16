package handler

import (
	"net/http"

	"github.com/carafie/identity/auth/domain"
	"github.com/carafie/identity/internal/clock"
)

func SetRefreshCookie(w http.ResponseWriter, refreshToken *domain.RefreshToken) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken.JWS,
		Path:     "/auth/tokens/refresh",
		MaxAge:   clock.SecondsUntil(refreshToken.ExpiresAt),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func GetRefreshCookie(r *http.Request) (*http.Cookie, error) {
	return r.Cookie("refresh_token")
}
