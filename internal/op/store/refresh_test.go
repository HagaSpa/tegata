package store

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newFixedRefreshTokens(t *testing.T) *RefreshTokens {
	t.Helper()
	s := NewRefreshTokens()
	s.now = func() time.Time { return testBase }
	return s
}

func advanceRefresh(s *RefreshTokens, d time.Duration) {
	s.now = func() time.Time { return testBase.Add(d) }
}

func mustRotate(t *testing.T, s *RefreshTokens, key string) (string, *RefreshToken) {
	t.Helper()
	nextKey, next, err := s.Rotate(key, "client-1")
	if err != nil {
		t.Fatalf("Rotate() failed: %v", err)
	}
	return nextKey, next
}

func TestRefreshTokens(t *testing.T) {
	const day = 24 * time.Hour

	t.Run("発行した内容が保存される", func(t *testing.T) {
		s := newFixedRefreshTokens(t)
		key := s.Issue("client-1", "u-0001", "openid offline_access")
		got := s.tokens[key]

		if got == nil {
			t.Fatalf("tokens[%q] = nil, want saved", key)
		}
		if got.ClientID != "client-1" || got.Sub != "u-0001" || got.Scope != "openid offline_access" {
			t.Errorf("saved = %+v, want client-1 / u-0001 / openid offline_access", *got)
		}
		if want := testBase.Add(30 * day); !got.ExpiresAt.Equal(want) {
			t.Errorf("saved = %v, want %v", got.ExpiresAt, want)
		}
		if got.FamilyID == "" {
			t.Errorf("FamilyID is empty")
		}
		if got.used {
			t.Errorf("used = true, want false")
		}
	})

	t.Run("発行のたび別の系統になる", func(t *testing.T) {
		s := newFixedRefreshTokens(t)
		key1 := s.Issue("client-1", "u-0001", "openid offline_access")
		key2 := s.Issue("client-1", "u-0001", "openid offline_access")

		if key1 == key2 {
			t.Fatalf("Issue() returned the same key twice: %s", key1)
		}
		if s.tokens[key1].FamilyID == s.tokens[key2].FamilyID {
			t.Errorf("FamilyID is shared between two Issue() calls")
		}
	})

	t.Run("Rotate は系統と期限を引き継いだ新しいトークンを返す", func(t *testing.T) {
		s := newFixedRefreshTokens(t)
		key := s.Issue("client-1", "u-0001", "openid offline_access")
		first := s.tokens[key]
		advanceRefresh(s, day)
		nextKey, next := mustRotate(t, s, key)

		if nextKey == key {
			t.Errorf("Rotate() returned the same key")
		}
		if next.ClientID != "client-1" || next.Sub != "u-0001" || next.Scope != "openid offline_access" {
			t.Errorf("next = %+v, want client-1 / u-0001 / openid offline_access", *next)
		}
		if next.FamilyID != first.FamilyID {
			t.Errorf("FamilyID = %q, want %q", next.FamilyID, first.FamilyID)
		}
		if !next.ExpiresAt.Equal(first.ExpiresAt) {
			t.Errorf("ExpiresAt = %v, want %v (not extended)", next.ExpiresAt, first.ExpiresAt)
		}
		if s.tokens[nextKey] != next {
			t.Errorf("tokens[nextKey] is not the returned record")
		}
	})

	t.Run("新しいトークンはさらに Rotate できる", func(t *testing.T) {
		s := newFixedRefreshTokens(t)
		key1 := s.Issue("client-1", "u-0001", "openid offline_access")
		key2, _ := mustRotate(t, s, key1)
		key3, _ := mustRotate(t, s, key2)
		mustRotate(t, s, key3)
	})

	t.Run("使用済みを送ると系列ごと失効する", func(t *testing.T) {
		s := newFixedRefreshTokens(t)
		key1 := s.Issue("client-1", "u-0001", "openid offline_access")
		key2, _ := mustRotate(t, s, key1)

		if _, _, err := s.Rotate(key1, "client-1"); !errors.Is(err, ErrInvalidRefreshToken) {
			t.Fatalf("reuse Rotate(key1) error = %v, want ErrInvalidRefreshToken", err)
		}
		if _, _, err := s.Rotate(key2, "client-1"); !errors.Is(err, ErrInvalidRefreshToken) {
			t.Errorf("Rotate(key2) after reuse error = %v, want ErrInvalidRefreshToken", err)
		}
	})

	t.Run("再利用の検知は別の系列に影響しない", func(t *testing.T) {
		s := newFixedRefreshTokens(t)
		key1 := s.Issue("client-1", "u-0001", "openid offline_access")
		other := s.Issue("client-1", "u-0001", "openid offline_access")
		mustRotate(t, s, key1)

		if _, _, err := s.Rotate(key1, "client-1"); !errors.Is(err, ErrInvalidRefreshToken) {
			t.Fatalf("reuse Rotate(key1) error = %v, want ErrInvalidRefreshToken", err)
		}
		mustRotate(t, s, other)
	})

	t.Run("存在しないトークンは失敗する", func(t *testing.T) {
		s := newFixedRefreshTokens(t)

		nextKey, next, err := s.Rotate("no-such-token", "client-1")
		if !errors.Is(err, ErrInvalidRefreshToken) {
			t.Errorf("Rotate() error = %v, want ErrInvalidRefreshToken", err)
		}
		if nextKey != "" || next != nil {
			t.Errorf("Rotate() = %q, %+v; want empty", nextKey, next)
		}
	})

	t.Run("別のクライアントは失敗し、トークンは使用済みにならない", func(t *testing.T) {
		s := newFixedRefreshTokens(t)
		key := s.Issue("client-1", "u-0001", "openid offline_access")

		if _, _, err := s.Rotate(key, "client-2"); !errors.Is(err, ErrInvalidRefreshToken) {
			t.Fatalf("Rotate() by client-2 error = %v, want ErrInvalidRefreshToken", err)
		}
		mustRotate(t, s, key)
	})

	t.Run("期限", func(t *testing.T) {
		cases := []struct {
			name    string
			elapsed time.Duration
			wantErr bool
		}{
			{"直後は有効", 0, false},
			{"30 日ちょうどは有効", 30 * day, false},
			{"30 日 1 秒で失効", 30*day + time.Second, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				s := newFixedRefreshTokens(t)
				key := s.Issue("client-1", "u-0001", "openid offline_access")
				advanceRefresh(s, tc.elapsed)

				_, _, err := s.Rotate(key, "client-1")
				if tc.wantErr && !errors.Is(err, ErrInvalidRefreshToken) {
					t.Errorf("Rotate() error = %v, want ErrInvalidRefreshToken", err)
				}
				if !tc.wantErr && err != nil {
					t.Errorf("Rotate() error = %v, want nil", err)
				}
			})
		}
	})

	t.Run("Rotate しても系列の期限は延びない", func(t *testing.T) {
		s := newFixedRefreshTokens(t)
		key := s.Issue("client-1", "u-0001", "openid offline_access")
		advanceRefresh(s, 29*day)
		nextKey, _ := mustRotate(t, s, key)
		advanceRefresh(s, 30*day+time.Second)

		if _, _, err := s.Rotate(nextKey, "client-1"); !errors.Is(err, ErrInvalidRefreshToken) {
			t.Errorf("Rotate() after family expiry error = %v, want ErrInvalidRefreshToken", err)
		}
	})

	t.Run("同時に Rotate しても成功は 1 回だけ", func(t *testing.T) {
		s := newFixedRefreshTokens(t)
		key := s.Issue("client-1", "u-0001", "openid offline_access")

		const workers = 16
		var wg sync.WaitGroup
		var ok atomic.Int32
		start := make(chan struct{})
		for range workers {
			wg.Go(func() {
				<-start
				if _, _, err := s.Rotate(key, "client-1"); err == nil {
					ok.Add(1)
				}
			})
		}
		close(start)
		wg.Wait()

		if ok.Load() != 1 {
			t.Errorf("successful Rotate() = %d, want 1", ok.Load())
		}
	})
}

func TestRefreshTokens_Revoke(t *testing.T) {
	t.Run("失効すると Rotate できない", func(t *testing.T) {
		s := newFixedRefreshTokens(t)
		key := s.Issue("client-1", "u-0001", "openid offline_access")
		s.Revoke(key, "client-1")
		if _, _, err := s.Rotate(key, "client-1"); !errors.Is(err, ErrInvalidRefreshToken) {
			t.Errorf("Rotate() after Revoke error = %v, want ErrInvalidRefreshToken", err)
		}
	})

	t.Run("系列ごとに消える", func(t *testing.T) {
		s := newFixedRefreshTokens(t)
		key1 := s.Issue("client-1", "u-0001", "openid offline_access")
		key2, _ := mustRotate(t, s, key1)
		s.Revoke(key2, "client-1")
		if len(s.tokens) != 0 {
			t.Errorf("len(tokens) = %d, want 0 (used key1 must go too)", len(s.tokens))
		}
	})

	t.Run("別の系列には影響しない", func(t *testing.T) {
		s := newFixedRefreshTokens(t)
		key := s.Issue("client-1", "u-0001", "openid offline_access")
		other := s.Issue("client-1", "u-0001", "openid offline_access")
		s.Revoke(key, "client-1")
		mustRotate(t, s, other)
	})

	t.Run("別のクライアントは消せない", func(t *testing.T) {
		s := newFixedRefreshTokens(t)
		key := s.Issue("client-1", "u-0001", "openid offline_access")
		s.Revoke(key, "client-2")
		mustRotate(t, s, key)
	})

	t.Run("存在しないトークンは何もしない", func(t *testing.T) {
		s := newFixedRefreshTokens(t)
		key := s.Issue("client-1", "u-0001", "openid offline_access")
		s.Revoke("no-such-token", "client-1")
		mustRotate(t, s, key)
	})
}
