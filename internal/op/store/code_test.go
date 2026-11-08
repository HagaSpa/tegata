package store

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testBase = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

func newFixedCodes(t *testing.T) *Codes {
	t.Helper()
	s := NewCodes()
	s.now = func() time.Time { return testBase }
	return s
}

func advance(s *Codes, d time.Duration) {
	s.now = func() time.Time { return testBase.Add(d) }
}

func mustIssue(t *testing.T, s *Codes, sub string) string {
	t.Helper()
	key := s.Issue("client-1", "http://rp/cb", "openid", "challenge-1", "nonce-1", sub, s.now())
	return key
}

func TestCodes(t *testing.T) {
	t.Run("発行した内容がそのまま取り出せる", func(t *testing.T) {
		s := newFixedCodes(t)
		key := mustIssue(t, s, "u-0001")

		got, err := s.Consume(key)
		if err != nil {
			t.Fatalf("Consume() failed: %v", err)
		}
		want := Code{
			ClientID:      "client-1",
			RedirectURI:   "http://rp/cb",
			Scope:         "openid",
			CodeChallenge: "challenge-1",
			Nonce:         "nonce-1",
			Sub:           "u-0001",
			ExpiresAt:     testBase.Add(5 * time.Minute),
			AuthTime:      s.now(),
		}
		if *got != want {
			t.Errorf("Consume() = %+v, want %+v", *got, want)
		}
	})

	t.Run("2 回目の消費は失敗する", func(t *testing.T) {
		s := newFixedCodes(t)
		key := mustIssue(t, s, "u-0001")

		if _, err := s.Consume(key); err != nil {
			t.Fatalf("first Consume() failed: %v", err)
		}
		got, err := s.Consume(key)
		if !errors.Is(err, ErrInvalidCode) {
			t.Errorf("second Consume() error = %v, want ErrInvalidCode", err)
		}
		if got != nil {
			t.Errorf("second Consume() = %+v, want nil", got)
		}
	})

	t.Run("存在しないコードは失敗する", func(t *testing.T) {
		s := newFixedCodes(t)

		got, err := s.Consume("no-such-code")
		if !errors.Is(err, ErrInvalidCode) {
			t.Errorf("Consume() error = %v, want ErrInvalidCode", err)
		}
		if got != nil {
			t.Errorf("Consume() = %+v, want nil", got)
		}
	})

	t.Run("期限", func(t *testing.T) {
		cases := []struct {
			name    string
			elapsed time.Duration
			wantErr bool
		}{
			{"直後は有効", 0, false},
			{"5 分ちょうどは有効", 5 * time.Minute, false},
			{"5 分 1 秒で失効", 5*time.Minute + time.Second, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				s := newFixedCodes(t)
				key := mustIssue(t, s, "u-0001")
				advance(s, tc.elapsed)

				_, err := s.Consume(key)
				if tc.wantErr && !errors.Is(err, ErrInvalidCode) {
					t.Errorf("Consume() error = %v, want ErrInvalidCode", err)
				}
				if !tc.wantErr && err != nil {
					t.Errorf("Consume() error = %v, want nil", err)
				}
			})
		}
	})

	t.Run("期限切れのコードも消費時に消える", func(t *testing.T) {
		s := newFixedCodes(t)
		key := mustIssue(t, s, "u-0001")
		advance(s, 10*time.Minute)

		if _, err := s.Consume(key); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("expired Consume() error = %v, want ErrInvalidCode", err)
		}
		advance(s, 0)
		if _, err := s.Consume(key); !errors.Is(err, ErrInvalidCode) {
			t.Errorf("Consume() after expiry error = %v, want ErrInvalidCode", err)
		}
	})

	t.Run("別のコードは互いに干渉しない", func(t *testing.T) {
		s := newFixedCodes(t)
		key1 := mustIssue(t, s, "u-0001")
		key2 := mustIssue(t, s, "u-0002")
		if key1 == key2 {
			t.Fatalf("Issue() returned the same code twice: %s", key1)
		}

		got1, err := s.Consume(key1)
		if err != nil {
			t.Fatalf("Consume(key1) failed: %v", err)
		}
		got2, err := s.Consume(key2)
		if err != nil {
			t.Fatalf("Consume(key2) failed: %v", err)
		}
		if got1.Sub != "u-0001" || got2.Sub != "u-0002" {
			t.Errorf("Sub = %q, %q; want u-0001, u-0002", got1.Sub, got2.Sub)
		}
	})

	t.Run("コードは 43 文字の base64url", func(t *testing.T) {
		s := newFixedCodes(t)
		key := mustIssue(t, s, "u-0001")

		if len(key) != 43 {
			t.Errorf("len(code) = %d, want 43", len(key))
		}
		if strings.ContainsAny(key, "+/=") {
			t.Errorf("code %q contains characters outside base64url", key)
		}
	})

	t.Run("同時に消費しても成功は 1 回だけ", func(t *testing.T) {
		s := newFixedCodes(t)
		key := mustIssue(t, s, "u-0001")

		const workers = 16
		var wg sync.WaitGroup
		var ok atomic.Int32
		start := make(chan struct{})
		for range workers {
			wg.Go(func() {
				<-start
				if _, err := s.Consume(key); err == nil {
					ok.Add(1)
				}
			})
		}
		close(start)
		wg.Wait()

		if ok.Load() != 1 {
			t.Errorf("successful Consume() = %d, want 1", ok.Load())
		}
	})
}
