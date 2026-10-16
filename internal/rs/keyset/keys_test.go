package keyset

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"
)

func newFixJWK(t *testing.T) (*jwk, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to GenerateKey: %v", err)
	}
	hash := sha256.Sum256(key.PublicKey.N.Bytes())
	keyID := hex.EncodeToString(hash[:])
	n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
	return &jwk{
		Kty: "RSA", Kid: keyID, N: n, E: e,
	}, &key.PublicKey
}

func Test_parseJWK(t *testing.T) {
	t.Run("証明書の n,e が渡した jwk の n,e　と同じ", func(t *testing.T) {
		j, k := newFixJWK(t)
		want := &rsa.PublicKey{
			N: k.N,
			E: k.E,
		}
		got, gotErr := parseJWK(j)
		if gotErr != nil {
			t.Errorf("parseJWK() failed: %v", gotErr)
		}
		if got.E != want.E {
			t.Errorf("got.E = %v, want.E %v", got.E, want.E)
		}
		if got.N.Cmp(want.N) != 0 {
			t.Errorf("got.N = %v, want.N %v", got.N, want.N)
		}
	})
}
