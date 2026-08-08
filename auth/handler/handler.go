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
