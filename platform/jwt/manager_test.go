package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/carafie/identity/platform/email"
	"github.com/carafie/identity/platform/uuid"
	"github.com/google/go-cmp/cmp"
)

func TestManager_NewAndParse(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	manager := NewManager(publicKey, privateKey)

	tokenEmail, err := email.Parse("jwt@test")
	if err != nil {
		t.Fatalf("failed to parse email: %v", err)
	}
	wantToken := NewToken(
		uuid.New(),
		uuid.New(),
		tokenEmail,
		KindRefresh,
		time.Now(),
		time.Now().Add(1*time.Minute),
	)

	signedToken, err := manager.New(wantToken)
	if err != nil {
		t.Errorf("failed to create signed token: %v", err)
	}
	gotToken, err := manager.Parse(signedToken)
	if err != nil {
		t.Errorf("failed to parse signed token: %v", err)
	}
	if diff := cmp.Diff(wantToken, gotToken); diff != "" {
		t.Errorf("(-want +got):\n%s", diff)
	}
}
