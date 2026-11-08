package store

import (
	"errors"
	"testing"
	"time"
)

func newFixedSessions(t *testing.T) *Sessions {
	t.Helper()
	s := NewSessions()
	s.now = func() time.Time { return testBase }
	return s
}

func advanceSession(s *Sessions, d time.Duration) {
	s.now = func() time.Time { return testBase.Add(d) }
}

func TestSessions(t *testing.T) {
	t.Run("Save した内容が Get で取り出せる", func(t *testing.T) {
		s := newFixedSessions(t)
		key := s.Save("u-0001", s.now())

		got, err := s.Get(key)
		if err != nil {
			t.Fatalf("Get() failed: %v", err)
		}
		want := Session{
			Sub:       "u-0001",
			AuthTime:  testBase,
			ExpiresAt: testBase.Add(SessionTTL),
		}
		if *got != want {
			t.Errorf("Get() = %+v, want %+v", *got, want)
		}
	})

	t.Run("Get は何度でも引ける", func(t *testing.T) {
		s := newFixedSessions(t)
		key := s.Save("u-0001", s.now())

		for i := range 2 {
			if _, err := s.Get(key); err != nil {
				t.Fatalf("Get() #%d failed: %v", i+1, err)
			}
		}
	})

	t.Run("存在しない key は失敗する", func(t *testing.T) {
		s := newFixedSessions(t)

		got, err := s.Get("no-such-session")
		if !errors.Is(err, ErrInvalidSession) {
			t.Errorf("Get() error = %v, want ErrInvalidSession", err)
		}
		if got != nil {
			t.Errorf("Get() = %+v, want nil", got)
		}
	})

	t.Run("期限", func(t *testing.T) {
		cases := []struct {
			name    string
			elapsed time.Duration
			wantErr bool
		}{
			{"直後は有効", 0, false},
			{"10 時間ちょうどは有効", SessionTTL, false},
			{"10 時間 1 秒で失効", SessionTTL + time.Second, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				s := newFixedSessions(t)
				key := s.Save("u-0001", s.now())
				advanceSession(s, tc.elapsed)

				got, err := s.Get(key)
				if tc.wantErr {
					if !errors.Is(err, ErrInvalidSession) {
						t.Errorf("Get() error = %v, want ErrInvalidSession", err)
					}
					if got != nil {
						t.Errorf("Get() = %+v, want nil", got)
					}
				}
				if !tc.wantErr && err != nil {
					t.Errorf("Get() error = %v, want nil", err)
				}
			})
		}
	})

	t.Run("期限は AuthTime から数える", func(t *testing.T) {
		s := newFixedSessions(t)
		key := s.Save("u-0001", testBase.Add(-SessionTTL))
		advanceSession(s, time.Second)

		if _, err := s.Get(key); !errors.Is(err, ErrInvalidSession) {
			t.Errorf("Get() error = %v, want ErrInvalidSession", err)
		}
	})

	t.Run("別のセッションは互いに干渉しない", func(t *testing.T) {
		s := newFixedSessions(t)
		k1 := s.Save("u-0001", s.now())
		k2 := s.Save("u-0002", s.now())

		if k1 == k2 {
			t.Fatalf("Save() returned the same key twice: %q", k1)
		}
		for key, sub := range map[string]string{k1: "u-0001", k2: "u-0002"} {
			got, err := s.Get(key)
			if err != nil {
				t.Fatalf("Get(%q) failed: %v", key, err)
			}
			if got.Sub != sub {
				t.Errorf("Get(%q).Sub = %q, want %q", key, got.Sub, sub)
			}
		}
	})
}
