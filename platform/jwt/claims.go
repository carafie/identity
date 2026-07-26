package jwt

import "github.com/golang-jwt/jwt/v5"

type Claims struct {
	Kind  int    `json:"kind"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func NewClaims(token *Token) *Claims {
	return &Claims{
		Email: string(token.Email),
		Kind:  int(token.Kind),
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        token.ID.String(),
			Subject:   token.UserID.String(),
			IssuedAt:  jwt.NewNumericDate(token.CreatedAt),
			ExpiresAt: jwt.NewNumericDate(token.ExpiresAt),
		},
	}
}
