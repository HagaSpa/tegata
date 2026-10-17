package keyset

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
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

	t.Run("jwk.Kty が EC の場合はエラー", func(t *testing.T) {
		j, _ := newFixJWK(t)
		j.Kty = "EC"
		_, gotErr := parseJWK(j)
		if gotErr == nil {
			t.Error("jwk.Kty = EC should be error")
		}
	})
}

func newJWKServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func jwksBody(t *testing.T, keys ...*jwk) string {
	t.Helper()
	set := jwks{Keys: []jwk{}}
	for _, k := range keys {
		set.Keys = append(set.Keys, *k)
	}
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}
	return string(b)
}

func Test_fetch(t *testing.T) {
	rsaJWK, rsaKey := newFixJWK(t)
	ecJWK, _ := newFixJWK(t)
	ecJWK.Kty = "EC"
	brokenJWK, _ := newFixJWK(t)
	brokenJWK.N = "!!!"

	tests := []struct {
		name string
		keys []*jwk
		want map[string]*rsa.PublicKey
	}{
		{name: "RSA 鍵は1個", keys: []*jwk{rsaJWK}, want: map[string]*rsa.PublicKey{rsaJWK.Kid: rsaKey}},
		{name: "EC 鍵は読み飛ばす", keys: []*jwk{ecJWK, rsaJWK}, want: map[string]*rsa.PublicKey{rsaJWK.Kid: rsaKey}},
		{name: "n が壊れた RSA 鍵は読み飛ばす", keys: []*jwk{brokenJWK, rsaJWK}, want: map[string]*rsa.PublicKey{rsaJWK.Kid: rsaKey}},
		{name: "使える鍵がなければ空", keys: []*jwk{ecJWK}, want: map[string]*rsa.PublicKey{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newJWKServer(t, http.StatusOK, jwksBody(t, tt.keys...))
			got, err := fetch(http.DefaultClient, srv.URL)
			if err != nil {
				t.Fatalf("fetch() failed: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("len(got) = %d, want %d", len(got), len(tt.want))
			}
			for kid, want := range tt.want {
				g, ok := got[kid]
				if !ok {
					t.Errorf("got[%q] not found", kid)
					continue
				}
				if g.N.Cmp(want.N) != 0 || g.E != want.E {
					t.Errorf("got[%q] does not match want", kid)
				}
			}
		})
	}
}

func Test_fetch_Errors(t *testing.T) {
	rsaJWK, _ := newFixJWK(t)
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()

	tests := []struct {
		name string
		url  string
	}{
		{name: "200 以外の時", url: newJWKServer(t, http.StatusNotFound, jwksBody(t, rsaJWK)).URL},
		{name: "JSON ではない時", url: newJWKServer(t, http.StatusOK, "<html>").URL},
		{name: "接続できない時", url: closed.URL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fetch(http.DefaultClient, tt.url)
			if err == nil {
				t.Errorf("fetch() = %v, want error", got)
			}
		})
	}
}
