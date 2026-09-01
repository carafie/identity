package httpx

import "net/http"

type Handler func(r *http.Request) Response

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h(r).Respond(w)
}
