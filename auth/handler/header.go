package handler

import (
	"net/http"
	"strings"
)

func AccessJWSFromRequest(r *http.Request) string {
	tokenHeader := r.Header.Get("Authorization")
	if len(tokenHeader) < 7 || !strings.EqualFold(tokenHeader[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(tokenHeader[7:])
}
