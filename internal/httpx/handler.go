package httpx

import "net/http"

type Handler func(w http.ResponseWriter, r *http.Request) Response

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h(w, r).Respond(w)
}
