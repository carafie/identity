package domain

import (
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"testing"
	"time"

	"github.com/carafie/identity/internal/mail"
	"github.com/carafie/identity/internal/uuid"
)

func TestManager_SignAndParse(t *testing.T) {
	newManager := func(t *testing.T) *TokenManager {
		t.Helper()
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key pair: %v", err)
		}
		return NewTokenManager(publicKey, privateKey)
	}

	email, err := mail.Parse("token@test")
	if err != nil {
		t.Fatalf("failed to parse email: %v", err)
	}

	t.Run("keys mismatch", func(t *testing.T) {
		manager1 := newManager(t)
		manager2 := newManager(t)

		token := newToken(uuid.New(), email, KindRefresh, time.Hour)
		err := manager1.sign(token)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}
		_, err = manager2.parse(token.JWS)
		if err == nil {
			t.Error("parsing token with different key pair should fail")
		}
	})

	t.Run("token expired", func(t *testing.T) {
		manager := newManager(t)

		token := newToken(uuid.New(), email, KindRefresh, -time.Hour)
		err := manager.sign(token)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}
		_, err = manager.parse(token.JWS)
		if err == nil {
			t.Error("parsing expired token should fail")
		}
	})

	t.Run("success", func(t *testing.T) {
		manager := newManager(t)

		token := newToken(uuid.New(), email, KindRefresh, time.Hour)
		err := manager.sign(token)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}
		gotToken, err := manager.parse(token.JWS)
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}
		if !reflect.DeepEqual(gotToken, token) {
			t.Errorf(
				"signed then parsed token is different from initial\ngot=%#+v\nwant=%#+v",
				gotToken, token,
			)
		}
	})
}

func TestManager_SignAccessAndParseAccess(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	manager := NewTokenManager(publicKey, privateKey)

	email, err := mail.Parse("token@test")
	if err != nil {
		t.Fatalf("failed to parse email: %v", err)
	}

	t.Run("success", func(t *testing.T) {
		token := NewAccessToken(uuid.New(), email, time.Hour)
		err := manager.SignAccess(token)
		if err != nil {
			t.Fatalf("failed to sign access token: %v", err)
		}
		gotToken, err := manager.ParseAccess(token.JWS)
		if err != nil {
			t.Fatalf("failed to parse access token: %v", err)
		}
		if !reflect.DeepEqual(gotToken, token) {
			t.Errorf(
				"signed then parsed access token is different from initial\ngot=%#+v\nwant=%#+v",
				gotToken, token,
			)
		}
	})
}

func TestManager_SignRefreshAndParseRefresh(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	manager := NewTokenManager(publicKey, privateKey)

	email, err := mail.Parse("token@test")
	if err != nil {
		t.Fatalf("failed to parse email: %v", err)
	}

	t.Run("success", func(t *testing.T) {
		token := NewRefreshToken(uuid.New(), email, time.Hour)
		err := manager.SignRefresh(token)
		if err != nil {
			t.Fatalf("failed to sign refresh token: %v", err)
		}
		gotToken, err := manager.ParseRefresh(token.JWS)
		if err != nil {
			t.Fatalf("failed to parse refresh token: %v", err)
		}
		if !reflect.DeepEqual(gotToken, token) {
			t.Errorf(
				"signed then parsed refresh token is different from initial\ngot=%#+v\nwant=%#+v",
				gotToken, token,
			)
		}
	})
}
