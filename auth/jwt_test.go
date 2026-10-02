package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func newKeyManager(t *testing.T) *KeyManager {
	t.Helper()
	m, err := NewKeyManager()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func newFixedClaim(t *testing.T) *Claim {
	t.Helper()
	return &Claim{
		Iss:   "http://localhost:8000",
		Sub:   "u-0001",
		Aud:   "tegata-sample",
		Iat:   testBase.Unix(),
		Exp:   testBase.Unix(),
		Nonce: "EVKOT75CSF4I56CBZW",
	}
}

func TestKeyManager_Sign(t *testing.T) {
	t.Run("jwt に+/= が含まれていない", func(t *testing.T) {
		m := newKeyManager(t)
		claim := newFixedClaim(t)
		jwt, err := m.Sign(claim)
		if err != nil {
			t.Errorf("Sign() failed: %v", err)
			return
		}
		if strings.Contains(jwt.header, "+") || strings.Contains(jwt.header, "/") || strings.Contains(jwt.header, "=") {
			t.Error("jwt.header contains +,/,=")
			return
		}
		if strings.Contains(jwt.payload, "+") || strings.Contains(jwt.payload, "/") || strings.Contains(jwt.payload, "=") {
			t.Error("jwt.payload contains +,/,=")
			return
		}
		if strings.Contains(jwt.signature, "+") || strings.Contains(jwt.signature, "/") || strings.Contains(jwt.signature, "=") {
			t.Error("jwt.signature contains +,/,=")
			return
		}
	})

	t.Run("header の alg=RS256, kid=GetJWK().Kid となってること", func(t *testing.T) {
		m := newKeyManager(t)
		claim := newFixedClaim(t)
		jwt, err := m.Sign(claim)
		if err != nil {
			t.Errorf("Sign() failed: %v", err)
			return
		}
		dec, err := base64.RawURLEncoding.DecodeString(jwt.header)
		if err != nil {
			t.Errorf("Decode failed: %v", err)
			return
		}
		h := map[string]any{}
		err = json.Unmarshal(dec, &h)
		if err != nil {
			t.Errorf("Unmarshal failed: %v", err)
		}
		if h["alg"] != "RS256" {
			t.Error("alg is not RS256")
			return
		}
		if h["kid"] != m.GetJWKS().Keys[0].Kid {
			t.Error("kid is not KeyManager.GetJWKS().Keys[0].kid")
			return
		}
	})
}
