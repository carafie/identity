package email

import (
	"errors"
	"net/mail"
	"strings"

	"golang.org/x/text/unicode/norm"
)

var ErrInvalid = errors.New("email is invalid")

const (
	maxBytes      = 254
	maxLocalBytes = 64
)

type Email string

func Parse(email string) (Email, error) {
	if len(email) > maxBytes {
		return "", ErrInvalid
	}

	parsed, err := mail.ParseAddress(email)
	if err != nil {
		return "", ErrInvalid
	}
	if email != parsed.Address {
		return "", ErrInvalid
	}
	at := strings.LastIndex(parsed.Address, "@")
	if at == -1 || at > maxLocalBytes {
		return "", ErrInvalid
	}

	return Email(parsed.Address), nil
}

func (e Email) Normalize() Email {
	return Email(norm.NFC.String(strings.ToLower(string(e))))
}
