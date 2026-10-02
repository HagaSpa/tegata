package auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
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
			return
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

	t.Run("payload から claim が復元できること", func(t *testing.T) {
		m := newKeyManager(t)
		claim := newFixedClaim(t)
		jwt, err := m.Sign(claim)
		if err != nil {
			t.Errorf("Sign() failed: %v", err)
			return
		}
		dec, err := base64.RawURLEncoding.DecodeString(jwt.payload)
		if err != nil {
			t.Errorf("Decode failed: %v", err)
			return
		}
		p := map[string]any{}
		err = json.Unmarshal(dec, &p)
		if err != nil {
			t.Errorf("Unmarshal failed: %v", err)
			return
		}
		if p["iss"] != claim.Iss {
			t.Error("iss is invalid")
			return
		}
		if p["sub"] != claim.Sub {
			t.Error("sub is invalid")
			return
		}
		if p["aud"] != claim.Aud {
			t.Error("aud is invalid")
			return
		}
		if int64(p["iat"].(float64)) != claim.Iat {
			fmt.Print(reflect.TypeOf(p["iat"]))
			t.Error("iat is invalid")
			return
		}
		if int64(p["exp"].(float64)) != claim.Exp {
			t.Error("exp is invalid")
			return
		}
		if p["nonce"] != claim.Nonce {
			t.Error("nonce is invalid")
			return
		}
		if p["scope"] != claim.Scope {
			t.Error("scope is invalid")
			return
		}
		// if !reflect.DeepEqual(claim, p) {
		// 	t.Error("claim, payload in not same")
		// 	return
		// }
	})

	t.Run("signature の内容確認", func(t *testing.T) {
		m := newKeyManager(t)
		claim := newFixedClaim(t)
		jwt, err := m.Sign(claim)
		if err != nil {
			t.Errorf("Sign() failed: %v", err)
			return
		}
		digest := sha256.Sum256([]byte(jwt.header + "." + jwt.payload))
		dec, err := base64.RawURLEncoding.DecodeString(jwt.signature)
		if err != nil {
			t.Errorf("Decode failed: %v", err)
			return
		}
		err = rsa.VerifyPKCS1v15(&m.privateKey.PublicKey, crypto.SHA256, digest[:], dec)
		if err != nil {
			t.Errorf("VerifyPKCS1v15 is failed: %v", err)
			return
		}
	})
}
