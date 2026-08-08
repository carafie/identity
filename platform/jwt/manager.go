package jwt

import (
	"crypto/ed25519"
	"fmt"

	"github.com/carafie/identity/platform/mail"
	"github.com/carafie/identity/platform/uuid"
	"github.com/golang-jwt/jwt/v5"
)

type Manager struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	parser     *jwt.Parser
}

func NewManager(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) *Manager {
	if publicKey == nil {
		panic("public key cannot be nil")
	}
	if privateKey == nil {
		panic("private key cannot be nil")
	}
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

func (m *Manager) Sign(fields *TokenFields) (*Token, error) {
	claims := newClaims(fields)
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(m.privateKey)
	if err != nil {
		return nil, err
	}
	return newToken(fields, signed), nil
}

func (m *Manager) Parse(jws JWS) (*Token, error) {
	token, err := m.parser.ParseWithClaims(
		jws,
		&claims{},
		func(t *jwt.Token) (any, error) { return m.publicKey, nil },
	)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*claims)
	if !ok {
		// This should never happen.
		return nil, fmt.Errorf("unexpected claims type: %T", token.Claims)
	}

	id, err := uuid.Parse(claims.ID)
	if err != nil {
		return nil, err
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, err
	}
	email, err := mail.Parse(claims.Email)
	if err != nil {
		return nil, err
	}
	kind, err := ParseKind(claims.Kind)
	if err != nil {
		return nil, err
	}
	return newToken(
		loadTokenFields(id, userID, email, kind, claims.IssuedAt.Time, claims.ExpiresAt.Time),
		jws,
	), nil
}
