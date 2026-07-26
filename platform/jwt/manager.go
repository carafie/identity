package jwt

import (
	"crypto/ed25519"
	"fmt"

	"github.com/carafie/identity/platform/email"
	"github.com/carafie/identity/platform/uuid"
	"github.com/golang-jwt/jwt/v5"
)

type Manager struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	parser     *jwt.Parser
}

func NewManager(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) *Manager {
	return &Manager{
		publicKey:  publicKey,
		privateKey: privateKey,
		parser: jwt.NewParser(
			jwt.WithIssuedAt(),
			jwt.WithExpirationRequired(),
			jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		),
	}
}

func (m *Manager) New(token *Token) (string, error) {
	claims := NewClaims(token)
	signed, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(m.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}
	return signed, nil
}

func (m *Manager) Parse(token string) (*Token, error) {
	parsed, err := m.parser.ParseWithClaims(
		token,
		&Claims{},
		func(t *jwt.Token) (any, error) { return m.publicKey, nil },
	)
	if err != nil {
		return nil, err
	}

	if claims, ok := parsed.Claims.(*Claims); ok && parsed.Valid {
		return NewToken(
			uuid.MustParse(claims.ID),
			uuid.MustParse(claims.Subject),
			email.Email(claims.Email),
			Kind(claims.Kind),
			claims.IssuedAt.Time,
			claims.ExpiresAt.Time,
		), nil
	}
	return nil, fmt.Errorf("token is invalid")
}
