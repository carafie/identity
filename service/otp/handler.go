package otp

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/carafie/identity/platform/httpx"
	"github.com/carafie/identity/platform/mail"
	"github.com/carafie/identity/platform/requestid"
	"github.com/carafie/identity/platform/uuid"
	"github.com/carafie/identity/service/token"
)

type Handler struct {
	service *Service
}

type requestParams struct {
	Email string `json:"email"`
}

type requestResponse struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (h *Handler) Request(w http.ResponseWriter, r *http.Request) httpx.Response {
	requestID := requestid.FromContext(r.Context())

	var params requestParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		return httpx.Response{StatusCode: http.StatusBadRequest, RequestID: requestID}
	}

	otp, err := h.service.Request(r.Context(), params.Email)
	if err != nil {
		if errors.Is(err, mail.ErrInvalid) {
			return httpx.Response{StatusCode: http.StatusUnprocessableEntity, RequestID: requestID}
		}
		return httpx.Response{StatusCode: http.StatusInternalServerError, RequestID: requestID}
	}

	return httpx.Response{
		StatusCode: http.StatusCreated,
		RequestID:  requestID,
		Body:       requestResponse{ID: otp.ID.String(), ExpiresAt: otp.ExpiresAt},
	}
}

type confirmParams struct {
	Code string `json:"code"`
}

type confirmResponse struct {
	AccessToken string `json:"access_token"`
}

func (h *Handler) Confirm(w http.ResponseWriter, r *http.Request) httpx.Response {
	requestID := requestid.FromContext(r.Context())

	otpID := r.PathValue("id")

	var params confirmParams
	if err := json.NewDecoder(r.Body).Decode(&params); err != nil {
		return httpx.Response{StatusCode: http.StatusBadRequest, RequestID: requestID}
	}

	access, refresh, err := h.service.Confirm(r.Context(), otpID, params.Code)
	if err != nil {
		statusCode := http.StatusInternalServerError
		switch {
		case errors.Is(err, uuid.ErrInvalid),
			errors.Is(err, ErrCodeInvalid),
			errors.Is(err, ErrCodeMismatch):
			statusCode = http.StatusUnprocessableEntity
		case errors.Is(err, ErrCodeExpired):
			statusCode = http.StatusNotFound
		}
		return httpx.Response{StatusCode: statusCode, RequestID: requestID}
	}

	token.SetRefreshCookie(w, refresh)
	return httpx.Response{
		StatusCode: http.StatusCreated,
		RequestID:  requestID,
		Body:       confirmResponse{AccessToken: access},
	}
}
