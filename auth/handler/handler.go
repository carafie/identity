package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/carafie/identity/auth/domain"
	"github.com/carafie/identity/auth/service"
	"github.com/carafie/identity/platform/httpx"
	"github.com/carafie/identity/platform/mail"
	"github.com/carafie/identity/platform/requestid"
	"github.com/carafie/identity/platform/uuid"
)

type Handler struct {
	service *service.Service
}

type requestOTPParams struct {
	Email string `json:"email"`
}

type requestOTPResponse struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (h *Handler) RequestOTP(w http.ResponseWriter, r *http.Request) httpx.Response {
	requestID := requestid.FromContext(r.Context())

	var params requestOTPParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		return httpx.Response{StatusCode: http.StatusBadRequest, RequestID: requestID}
	}

	otp, err := h.service.RequestOTP(r.Context(), params.Email)
	if err != nil {
		if errors.Is(err, mail.ErrInvalid) {
			return httpx.Response{StatusCode: http.StatusUnprocessableEntity, RequestID: requestID}
		}
		return httpx.Response{StatusCode: http.StatusInternalServerError, RequestID: requestID}
	}

	return httpx.Response{
		StatusCode: http.StatusCreated,
		RequestID:  requestID,
		Body:       requestOTPResponse{ID: otp.ID.String(), ExpiresAt: otp.ExpiresAt},
	}
}

func (h *Handler) RegisterRequestOTP(mux *http.ServeMux) {
	mux.Handle("POST /auth/otps", httpx.Handler(h.RequestOTP))
}

type confirmOTPParams struct {
	Code string `json:"code"`
}

type confirmOTPResponse struct {
	AccessToken string `json:"access_token"`
}

func (h *Handler) ConfirmOTP(w http.ResponseWriter, r *http.Request) httpx.Response {
	requestID := requestid.FromContext(r.Context())

	otpID := r.PathValue("id")

	var params confirmOTPParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		return httpx.Response{StatusCode: http.StatusBadRequest, RequestID: requestID}
	}

	access, refresh, err := h.service.ConfirmOTP(r.Context(), otpID, params.Code)
	if err != nil {
		statusCode := http.StatusInternalServerError
		switch {
		case errors.Is(err, uuid.ErrInvalid),
			errors.Is(err, domain.ErrCodeInvalid),
			errors.Is(err, domain.ErrCodeMismatched):
			statusCode = http.StatusUnprocessableEntity
		case errors.Is(err, domain.ErrCodeExpired):
			statusCode = http.StatusNotFound
		}
		return httpx.Response{StatusCode: statusCode, RequestID: requestID}
	}

	SetRefreshCookie(w, refresh)
	return httpx.Response{
		StatusCode: http.StatusCreated,
		RequestID:  requestID,
		Body:       confirmOTPResponse{AccessToken: access.JWS},
	}
}

func (h *Handler) RegisterConfirmOTP(mux *http.ServeMux) {
	mux.Handle("POST /auth/otps/{id}", httpx.Handler(h.ConfirmOTP))
}

type refreshAccessTokenResponse struct {
	AccessToken string `json:"access_token"`
}

func (h *Handler) RefreshAccessToken(w http.ResponseWriter, r *http.Request) httpx.Response {
	requestID := requestid.FromContext(r.Context())

	refreshCookie, err := GetRefreshCookie(r)
	if err != nil {
		return httpx.Response{StatusCode: http.StatusUnauthorized, RequestID: requestID}
	}

	access, err := h.service.RefreshAccessToken(r.Context(), refreshCookie.Value)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if errors.Is(err, domain.ErrTokenInvalid) ||
			errors.Is(err, domain.ErrTokenExpired) ||
			errors.Is(err, domain.ErrTokenRevoked) {
			statusCode = http.StatusUnauthorized
		}
		return httpx.Response{StatusCode: statusCode, RequestID: requestID}
	}

	return httpx.Response{
		StatusCode: http.StatusCreated,
		RequestID:  requestID,
		Body:       refreshAccessTokenResponse{AccessToken: access.JWS},
	}
}

func (h *Handler) RegisterRefreshAccessToken(mux *http.ServeMux) {
	mux.Handle("POST /auth/tokens/refresh", httpx.Handler(h.RefreshAccessToken))
}

type listRefreshTokensResponse struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (h *Handler) ListRefreshTokens(w http.ResponseWriter, r *http.Request) httpx.Response {
	requestID := requestid.FromContext(r.Context())

	accessJWS := AccessJWSFromRequest(r)
	if accessJWS == "" {
		return httpx.Response{StatusCode: http.StatusUnauthorized, RequestID: requestID}
	}
	tokens, err := h.service.ListRefreshTokens(r.Context(), accessJWS)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if errors.Is(err, domain.ErrTokenInvalid) {
			statusCode = http.StatusUnauthorized
		}
		return httpx.Response{StatusCode: statusCode, RequestID: requestID}
	}

	body := make([]listRefreshTokensResponse, len(tokens))
	for _, token := range tokens {
		body = append(body, listRefreshTokensResponse{
			ID:        token.ID.String(),
			CreatedAt: token.CreatedAt,
			ExpiresAt: token.ExpiresAt,
		})
	}

	return httpx.Response{
		StatusCode: http.StatusOK,
		RequestID:  requestID,
		Body:       body,
	}
}

func (h *Handler) RegisterListRefreshTokens(mux *http.ServeMux) {
	mux.Handle("GET /auth/tokens", httpx.Handler(h.ListRefreshTokens))
}

func (h *Handler) RevokeRefreshToken(w http.ResponseWriter, r *http.Request) httpx.Response {
	requestID := requestid.FromContext(r.Context())

	refreshTokenID := r.PathValue("id")

	accessJWS := AccessJWSFromRequest(r)
	if accessJWS == "" {
		return httpx.Response{StatusCode: http.StatusUnauthorized, RequestID: requestID}
	}
	err := h.service.RevokeRefreshToken(r.Context(), accessJWS, refreshTokenID)
	if err != nil {
		statusCode := http.StatusInternalServerError
		switch {
		case errors.Is(err, domain.ErrTokenInvalid):
			statusCode = http.StatusUnauthorized
		case errors.Is(err, domain.ErrTokenNotFound):
			statusCode = http.StatusNotFound
		}
		return httpx.Response{StatusCode: statusCode, RequestID: requestID}
	}

	return httpx.Response{
		StatusCode: http.StatusNoContent,
		RequestID:  requestID,
	}
}

func (h *Handler) RegisterRevokeRefreshToken(mux *http.ServeMux) {
	mux.Handle("DELETE /auth/tokens/{id}", httpx.Handler(h.RevokeRefreshToken))
}

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) httpx.Response {
	requestID := requestid.FromContext(r.Context())

	userID := r.PathValue("id")

	accessJWS := AccessJWSFromRequest(r)
	if accessJWS == "" {
		return httpx.Response{StatusCode: http.StatusUnauthorized, RequestID: requestID}
	}
	if err := h.service.DeleteUser(r.Context(), accessJWS, userID); err != nil {
		statusCode := http.StatusInternalServerError
		switch {
		case errors.Is(err, domain.ErrTokenInvalid):
			statusCode = http.StatusUnauthorized
		case errors.Is(err, uuid.ErrInvalid):
			statusCode = http.StatusUnprocessableEntity
		case errors.Is(err, domain.ErrUserNotFound):
			statusCode = http.StatusNotFound
		}
		return httpx.Response{StatusCode: statusCode, RequestID: requestID}
	}

	return httpx.Response{
		StatusCode: http.StatusNoContent,
		RequestID:  requestID,
	}
}

func (h *Handler) RegisterDeleteUser(mux *http.ServeMux) {
	mux.Handle("DELETE /auth/users/{id}", httpx.Handler(h.DeleteUser))
}
