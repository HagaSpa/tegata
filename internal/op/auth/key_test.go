package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/HagaSpa/tegata/internal/jwt"
)

func newKeyManager(t *testing.T) *KeyManager {
	t.Helper()
	m, err := NewKeyManager()
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return testBase }
	return m
}

func newFixedClaims() *jwt.Claims {
	return &jwt.Claims{
		Iss: "http://localhost:8080",
		Sub: "u-0001",
		Aud: "tegata-sample",
		Iat: testBase.Unix(),
		Exp: testBase.Add(time.Hour).Unix(),
	}
}

func TestKeyManager(t *testing.T) {
	t.Run("自分で Sign したトークンは Verify できる", func(t *testing.T) {
		m := newKeyManager(t)
		tok, err := m.Sign(newFixedClaims())
		if err != nil {
			t.Fatalf("Sign() failed: %v", err)
		}
		if _, err := m.Verify(tok.String()); err != nil {
			t.Errorf("Verify() failed: %v", err)
		}
	})

	t.Run("JWKS の kid で署名している", func(t *testing.T) {
		m := newKeyManager(t)
		if _, err := m.publicKey(m.JWKS().Keys[0].Kid); err != nil {
			t.Errorf("publicKey(JWKS kid) failed: %v", err)
		}
	})

	t.Run("別の KeyManager が署名したトークンは Verify できない", func(t *testing.T) {
		other := newKeyManager(t)
		tok, err := other.Sign(newFixedClaims())
		if err != nil {
			t.Fatalf("Sign() failed: %v", err)
		}
		if _, err := newKeyManager(t).Verify(tok.String()); !errors.Is(err, ErrUnknownKey) {
			t.Errorf("Verify() error = %v, want ErrUnknownKey", err)
		}
	})

	t.Run("期限切れは ErrExpired", func(t *testing.T) {
		m := newKeyManager(t)
		tok, err := m.Sign(newFixedClaims())
		if err != nil {
			t.Fatalf("Sign() failed: %v", err)
		}
		m.now = func() time.Time { return testBase.Add(time.Hour) }
		if _, err := m.Verify(tok.String()); !errors.Is(err, jwt.ErrExpired) {
			t.Errorf("Verify() error = %v, want jwt.ErrExpired", err)
		}
	})
}
