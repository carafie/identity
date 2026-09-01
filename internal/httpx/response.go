package httpx

import (
	"encoding/json/v2"
	"net/http"
	"uuid"
)

type Response struct {
	StatusCode int
	RequestID  uuid.UUID
	Cookies    []*http.Cookie
	Body       any
}

func (r Response) Respond(w http.ResponseWriter) {
	w.Header().Add("X-Request-ID", r.RequestID.String())

	for _, cookie := range r.Cookies {
		http.SetCookie(w, cookie)
	}

	if r.Body != nil {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(r.StatusCode)
		json.MarshalWrite(w, r.Body)
	} else {
		w.WriteHeader(r.StatusCode)
	}
}
