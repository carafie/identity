package handler

import (
	"net/http"

	"github.com/carafie/identity/auth/domain"
	"github.com/carafie/identity/internal/clock"
)

func NewRefreshTokenCookie(refreshToken *domain.RefreshToken) *http.Cookie {
	return &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken.JWS,
		Path:     "/auth/tokens/refresh",
		MaxAge:   clock.SecondsUntil(refreshToken.ExpiresAt),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func GetRefreshTokenCookie(r *http.Request) (*http.Cookie, error) {
	return r.Cookie("refresh_token")
}
