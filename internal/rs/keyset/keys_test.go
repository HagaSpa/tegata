package keyset

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

type closeTrackingBody struct {
	io.ReadCloser
	closed *bool
}

func (b closeTrackingBody) Close() error {
	*b.closed = true
	return b.ReadCloser.Close()
}

type closeTrackinggTransport struct {
	closed *bool
}

func (t closeTrackinggTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body = closeTrackingBody{ReadCloser: resp.Body, closed: t.closed}
	return resp, nil
}

func Test_fetch_ClosesBody(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "200", status: http.StatusOK, body: `{"keys":[]}`},
		{name: "200 以外", status: http.StatusNotFound, body: "not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newJWKServer(t, tt.status, tt.body)
			closed := false
			client := &http.Client{Transport: closeTrackinggTransport{closed: &closed}}
			_, _ = fetch(client, srv.URL)
			if !closed {
				t.Errorf("resp.Body is not closed")
			}
		})
	}
}

type fakeOP struct {
	url    string
	body   atomic.Value
	status atomic.Int32
	hits   atomic.Int32
}

func newFakeOP(t *testing.T, body string) *fakeOP {
	t.Helper()
	op := &fakeOP{}
	op.body.Store(body)
	op.status.Store(http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op.hits.Add(1)
		w.WriteHeader(int(op.status.Load()))
		w.Write([]byte(op.body.Load().(string)))
	}))
	t.Cleanup(srv.Close)
	op.url = srv.URL
	return op
}

type fakeClock struct {
	current time.Time
}

func (c *fakeClock) now() time.Time {
	return c.current
}

func (c *fakeClock) advance(d time.Duration) {
	c.current = c.current.Add(d)
}

func newTestKeySet(op *fakeOP) (*KeySet, *fakeClock) {
	clock := &fakeClock{current: time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)}
	ks := NewKeySet(http.DefaultClient, op.url)
	ks.now = clock.now
	return ks, clock
}

func TestKeySet_Key(t *testing.T) {
	a, aKey := newFixJWK(t)
	b, bKey := newFixJWK(t)
	aBody := jwksBody(t, a)
	bBody := jwksBody(t, b)

	tests := []struct {
		name     string
		edit     func(ks *KeySet, op *fakeOP, clock *fakeClock)
		kid      string
		want     *rsa.PublicKey
		wantErr  error
		wantHits int32
	}{
		{
			name:     "キャッシュ済みのkidは取りに行かない",
			kid:      a.Kid,
			want:     aKey,
			wantHits: 1,
		},
		{
			name: "29秒経った時に、未知のkidが渡されてもfetchしない",
			edit: func(ks *KeySet, op *fakeOP, clock *fakeClock) {
				clock.advance(29 * time.Second)
			},
			kid:      "unknown",
			wantErr:  ErrUnknownKey,
			wantHits: 1,
		},
		{
			name: "30秒経った時に、未知のkidが渡されたらfetchする",
			edit: func(ks *KeySet, op *fakeOP, clock *fakeClock) {
				clock.advance(30 * time.Second)
			},
			kid:      "unknown",
			wantErr:  ErrUnknownKey,
			wantHits: 2,
		},
		{
			name: "OP再起動後の新しいkidはfetchして返す",
			edit: func(ks *KeySet, op *fakeOP, clock *fakeClock) {
				op.body.Store(bBody)
				clock.advance(time.Minute)
			},
			kid:      b.Kid,
			want:     bKey,
			wantHits: 2,
		},
		{
			name: "fetchした直後に、以前持っていたkidは取得できない",
			edit: func(ks *KeySet, op *fakeOP, clock *fakeClock) {
				op.body.Store(bBody)
				clock.advance(time.Minute)
				ks.Key(b.Kid)
			},
			kid:      a.Kid,
			wantErr:  ErrUnknownKey,
			wantHits: 2,
		},
		{
			name: "OP障害中もキャッシュ済みのkidは返される",
			edit: func(ks *KeySet, op *fakeOP, clock *fakeClock) {
				op.status.Store(http.StatusInternalServerError)
				clock.advance(time.Minute)
				ks.Key("unknown")
			},
			kid:      a.Kid,
			want:     aKey,
			wantHits: 2,
		},
		{
			name: "取得に失敗した10秒後に、未知のkidが渡されてもfetchしない",
			edit: func(ks *KeySet, op *fakeOP, clock *fakeClock) {
				op.status.Store(http.StatusInternalServerError)
				clock.advance(time.Minute)
				ks.Key("unknown")
				clock.advance(10 * time.Second)
			},
			kid:      "unknown",
			wantErr:  ErrUnknownKey,
			wantHits: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := newFakeOP(t, aBody)
			ks, clock := newTestKeySet(op)
			if _, err := ks.Key(a.Kid); err != nil {
				t.Fatalf("first Key() failed: %v", err)
			}
			if tt.edit != nil {
				tt.edit(ks, op, clock)
			}

			got, err := ks.Key(tt.kid)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Key() error = %v, want %v", err, tt.wantErr)
			}
			if tt.want == nil {
				if got != nil {
					t.Errorf("Key() returned a key, want nil")
				}
			} else if got == nil || !got.Equal(tt.want) {
				t.Errorf("Key() does not return the want key")
			}
			if hits := op.hits.Load(); hits != tt.wantHits {
				t.Errorf("hits = %d, want %d", hits, tt.wantHits)
			}
		})
	}
}

func TestKeySet_Key_FetchErrors(t *testing.T) {
	a, _ := newFixJWK(t)
	aBody := jwksBody(t, a)

	tests := []struct {
		name     string
		edit     func(ks *KeySet, op *fakeOP, clock *fakeClock)
		wantHits int32
	}{
		{
			name: "初回からOP障害",
			edit: func(ks *KeySet, op *fakeOP, clock *fakeClock) {
				ks.Key(a.Kid)
				op.status.Store(http.StatusInternalServerError)
				clock.advance(time.Minute)
			},
			wantHits: 2,
		},
		{
			name: "キャッシュした後にOP障害",
			edit: func(ks *KeySet, op *fakeOP, clock *fakeClock) {
				ks.Key(a.Kid)
				op.status.Store(http.StatusInternalServerError)
				clock.advance(time.Minute)
			},
			wantHits: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := newFakeOP(t, aBody)
			ks, clock := newTestKeySet(op)
			tt.edit(ks, op, clock)

			got, err := ks.Key("unknown")
			if err == nil || errors.Is(err, ErrUnknownKey) {
				t.Errorf("Keys() error = %v, want fetch error", err)
			}
			if got != nil {
				t.Errorf("Key() returned a key, want nil")
			}
			if hits := op.hits.Load(); hits != tt.wantHits {
				t.Errorf("hits=%d,want %d", hits, tt.wantHits)
			}
		})
	}
}

func TestKeySet_Key_Concurrent(t *testing.T) {
	a, _ := newFixJWK(t)
	op := newFakeOP(t, jwksBody(t, a))
	ks, clock := newTestKeySet(op)
	if _, err := ks.Key(a.Kid); err != nil {
		t.Fatalf("first Key() failed: %v", err)
	}
	clock.advance(time.Minute)

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			ks.Key("unknown")
		})
	}
	wg.Wait()
	if hits := op.hits.Load(); hits != 2 {
		t.Errorf("hits = %d, want 2", hits)
	}
}
