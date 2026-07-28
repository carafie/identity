package jwt

import "github.com/golang-jwt/jwt/v5"

type claims struct {
	Email string `json:"email"`
	Kind  int    `json:"kind"`
	jwt.RegisteredClaims
}

func newClaims(fields *TokenFields) *claims {
	return &claims{
		Email: string(fields.Email),
		Kind:  int(fields.Kind),
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        fields.ID.String(),
			Subject:   fields.UserID.String(),
			IssuedAt:  jwt.NewNumericDate(fields.CreatedAt),
			ExpiresAt: jwt.NewNumericDate(fields.ExpiresAt),
		},
	}
}
