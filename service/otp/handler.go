package otp

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/carafie/identity/platform/email"
	"github.com/carafie/identity/platform/httpx"
	"github.com/carafie/identity/platform/requestid"
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
		if errors.Is(err, email.ErrInvalid) {
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
