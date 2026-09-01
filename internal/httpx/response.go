package httpx

import (
	"encoding/json/v2"
	"net/http"
	"uuid"
)

type Response struct {
	StatusCode int
	RequestID  uuid.UUID
	Body       any
}

func (r Response) Respond(w http.ResponseWriter) {
	w.Header().Add("Content-Type", "application/json")
	w.Header().Add("X-Request-ID", r.RequestID.String())
	w.WriteHeader(r.StatusCode)
	if r.Body != nil {
		json.MarshalWrite(w, r.Body)
	}
}
