package jwt

import "errors"

var ErrKindInvalid = errors.New("kind is invalid")

type Kind int

const (
	kindUnknown Kind = iota
	KindAccess
	KindRefresh
)

func ParseKind(kind int) (Kind, error) {
	switch kind {
	case int(KindAccess):
		return KindAccess, nil
	case int(KindRefresh):
		return KindRefresh, nil
	default:
		return kindUnknown, ErrKindInvalid
	}
}
