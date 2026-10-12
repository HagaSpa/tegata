package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testKid = "kid-1"

var testBase = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func keyFor(key *rsa.PrivateKey) KeyFunc {
	return func(kid string) (*rsa.PublicKey, error) {
		if kid != testKid {
			return nil, errors.New("unknown kid")
		}
		return &key.PublicKey, nil
	}
}

func newFixedClaims() *Claims {
	return &Claims{
		Iss:   "http://localhost:8080",
		Sub:   "u-0001",
		Aud:   "tegata-sample",
		Iat:   testBase.Unix(),
		Exp:   testBase.Add(time.Hour).Unix(),
		Nonce: "EVKOT75CSF4I56CBZW",
		Scope: "test",
	}
}

func mustSign(t *testing.T, key *rsa.PrivateKey, kid string, claims *Claims) *Token {
	t.Helper()
	tok, err := Sign(key, kid, claims)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	return tok
}

func encodeSegment(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestSign(t *testing.T) {
	t.Run("3 つの部分に +/= が含まれていない", func(t *testing.T) {
		tok := mustSign(t, newKey(t), testKid, newFixedClaims())
		for name, part := range map[string]string{"header": tok.header, "payload": tok.payload, "signature": tok.signature} {
			if strings.ContainsAny(part, "+/=") {
				t.Errorf("%s contains +, / or =: %q", name, part)
			}
		}
	})

	t.Run("header は alg=RS256 と渡した kid", func(t *testing.T) {
		tok := mustSign(t, newKey(t), testKid, newFixedClaims())
		dec, err := base64.RawURLEncoding.DecodeString(tok.header)
		if err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		h := map[string]any{}
		if err := json.Unmarshal(dec, &h); err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}
		if h["alg"] != "RS256" || h["kid"] != testKid {
			t.Errorf("header = %v, want alg=RS256 kid=%s", h, testKid)
		}
	})

	t.Run("payload から claims が復元できる", func(t *testing.T) {
		claims := newFixedClaims()
		tok := mustSign(t, newKey(t), testKid, claims)
		dec, err := base64.RawURLEncoding.DecodeString(tok.payload)
		if err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		got := Claims{}
		if err := json.Unmarshal(dec, &got); err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}
		if got != *claims {
			t.Errorf("payload = %+v, want %+v", got, *claims)
		}
	})

	t.Run("signature は header.payload の RS256 署名", func(t *testing.T) {
		key := newKey(t)
		tok := mustSign(t, key, testKid, newFixedClaims())
		digest := sha256.Sum256([]byte(tok.header + "." + tok.payload))
		sig, err := base64.RawURLEncoding.DecodeString(tok.signature)
		if err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
			t.Errorf("VerifyPKCS1v15 failed: %v", err)
		}
	})
}

func TestVerify(t *testing.T) {
	t.Run("Sign した結果を Verify すると同じ claims になる", func(t *testing.T) {
		key := newKey(t)
		claims := newFixedClaims()
		tok := mustSign(t, key, testKid, claims)

		got, err := Verify(tok.String(), keyFor(key), testBase)
		if err != nil {
			t.Fatalf("Verify() failed: %v", err)
		}
		if !reflect.DeepEqual(claims, got) {
			t.Errorf("Verify() = %+v, want %+v", got, claims)
		}
	})

	t.Run("失敗するケース", func(t *testing.T) {
		key := newKey(t)
		other := newKey(t)
		valid := mustSign(t, key, testKid, newFixedClaims())
		expiredClaims := newFixedClaims()
		expiredClaims.Exp = testBase.Unix()
		expired := mustSign(t, key, testKid, expiredClaims)
		noneHeader := encodeSegment(t, map[string]any{"alg": "none", "kid": testKid})
		noKidHeader := encodeSegment(t, map[string]any{"alg": "RS256"})

		cases := []struct {
			name    string
			token   string
			keyFor  KeyFunc
			wantErr error
		}{
			{"3 分割でない", "a.b", keyFor(key), nil},
			{"signature の改竄", valid.String() + "a", keyFor(key), nil},
			{"payload の改竄", valid.header + "." + valid.payload + "a." + valid.signature, keyFor(key), nil},
			{"別の鍵で署名されている", mustSign(t, other, testKid, newFixedClaims()).String(), keyFor(key), nil},
			{"未知の kid", mustSign(t, key, "kid-2", newFixedClaims()).String(), keyFor(key), nil},
			{"alg が none", noneHeader + "." + valid.payload + "." + valid.signature, keyFor(key), nil},
			{"kid が無い", noKidHeader + "." + valid.payload + "." + valid.signature, keyFor(key), nil},
			{"exp ちょうどで失効", expired.String(), keyFor(key), ErrExpired},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := Verify(tc.token, tc.keyFor, testBase)
				if err == nil {
					t.Fatalf("Verify() = %+v, want error", got)
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Errorf("Verify() error = %v, want %v", err, tc.wantErr)
				}
			})
		}
	})
}
