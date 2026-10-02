package auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
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
		Scope: "test",
	}
}

func TestKeyManager_Sign(t *testing.T) {
	t.Run("jwt に+/= が含まれていない", func(t *testing.T) {
		m := newKeyManager(t)
		claim := newFixedClaim(t)
		jwt, err := m.Sign(claim)
		if err != nil {
			t.Fatalf("Sign() failed: %v", err)
		}
		if strings.Contains(jwt.header, "+") || strings.Contains(jwt.header, "/") || strings.Contains(jwt.header, "=") {
			t.Error("jwt.header contains +,/,=")
		}
		if strings.Contains(jwt.payload, "+") || strings.Contains(jwt.payload, "/") || strings.Contains(jwt.payload, "=") {
			t.Error("jwt.payload contains +,/,=")
		}
		if strings.Contains(jwt.signature, "+") || strings.Contains(jwt.signature, "/") || strings.Contains(jwt.signature, "=") {
			t.Error("jwt.signature contains +,/,=")
		}
	})

	t.Run("header の alg=RS256, kid=GetJWK().Kid となってること", func(t *testing.T) {
		m := newKeyManager(t)
		claim := newFixedClaim(t)
		jwt, err := m.Sign(claim)
		if err != nil {
			t.Fatalf("Sign() failed: %v", err)
		}
		dec, err := base64.RawURLEncoding.DecodeString(jwt.header)
		if err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		h := map[string]any{}
		err = json.Unmarshal(dec, &h)
		if err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}
		if h["alg"] != "RS256" {
			t.Error("alg is not RS256")
		}
		if h["kid"] != m.GetJWKS().Keys[0].Kid {
			t.Error("kid is not KeyManager.GetJWKS().Keys[0].kid")
		}
	})

	t.Run("payload から claim が復元できること", func(t *testing.T) {
		m := newKeyManager(t)
		claim := newFixedClaim(t)
		jwt, err := m.Sign(claim)
		if err != nil {
			t.Fatalf("Sign() failed: %v", err)
		}
		dec, err := base64.RawURLEncoding.DecodeString(jwt.payload)
		if err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		p := map[string]any{}
		err = json.Unmarshal(dec, &p)
		if err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}
		if p["iss"] != claim.Iss {
			t.Error("iss is invalid")
		}
		if p["sub"] != claim.Sub {
			t.Error("sub is invalid")
		}
		if p["aud"] != claim.Aud {
			t.Error("aud is invalid")
		}
		if int64(p["iat"].(float64)) != claim.Iat {
			t.Error("iat is invalid")
		}
		if int64(p["exp"].(float64)) != claim.Exp {
			t.Error("exp is invalid")
		}
		if p["nonce"] != claim.Nonce {
			t.Error("nonce is invalid")
		}
		if p["scope"] != claim.Scope {
			t.Error("scope is invalid")
		}
	})

	t.Run("signature の内容確認", func(t *testing.T) {
		m := newKeyManager(t)
		claim := newFixedClaim(t)
		jwt, err := m.Sign(claim)
		if err != nil {
			t.Fatalf("Sign() failed: %v", err)
		}
		digest := sha256.Sum256([]byte(jwt.header + "." + jwt.payload))
		dec, err := base64.RawURLEncoding.DecodeString(jwt.signature)
		if err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		err = rsa.VerifyPKCS1v15(&m.privateKey.PublicKey, crypto.SHA256, digest[:], dec)
		if err != nil {
			t.Errorf("VerifyPKCS1v15 is failed: %v", err)
		}
	})
}
