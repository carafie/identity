package token

import (
	"net/http"
)

func SetRefreshCookie(w http.ResponseWriter, token Refresh) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    token.Token,
		Path:     "/auth/token/refresh",
		MaxAge:   token.SecondsLeft(),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func UnsetRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/auth/token/refresh",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
