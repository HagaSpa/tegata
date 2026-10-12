package store

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newFixedAuthorizeRequests(t *testing.T) *AuthorizeRequests {
	t.Helper()
	s := NewAuthorizeRequests()
	s.now = func() time.Time { return testBase }
	return s
}

func advanceAuthorize(s *AuthorizeRequests, d time.Duration) {
	s.now = func() time.Time { return testBase.Add(d) }
}

func validAuthorizeRequest() *AuthorizeRequest {
	return &AuthorizeRequest{
		ClientID:            "client-1",
		RedirectURI:         "http://rp/cb",
		ResponseType:        "code",
		Scope:               "openid",
		State:               "state-1",
		Nonce:               "nonce-1",
		CodeChallenge:       "challenge-1",
		CodeChallengeMethod: "S256",
	}
}

func mustSave(t *testing.T, s *AuthorizeRequests, req *AuthorizeRequest) string {
	t.Helper()
	key, err := s.Save(req)
	if err != nil {
		t.Fatalf("failed save err = %v", err)
	}
	return key
}

func TestAuthorizeRequests(t *testing.T) {
	t.Run("保存した内容が取り出せる", func(t *testing.T) {
		s := newFixedAuthorizeRequests(t)
		req := validAuthorizeRequest()
		key := mustSave(t, s, req)

		got, err := s.Find(key)
		if err != nil {
			t.Fatalf("Find() failed: %v", err)
		}
		want := AuthorizeRequest{
			ClientID:            "client-1",
			RedirectURI:         "http://rp/cb",
			ResponseType:        "code",
			Scope:               "openid",
			State:               "state-1",
			Nonce:               "nonce-1",
			CodeChallenge:       "challenge-1",
			CodeChallengeMethod: "S256",
			ExpiresAt:           testBase.Add(10 * time.Minute),
		}
		if *got != want {
			t.Errorf("Find() = %+v, want %+v", *got, want)
		}
	})

	t.Run("Find は2回呼び出せる", func(t *testing.T) {
		s := newFixedAuthorizeRequests(t)
		req := validAuthorizeRequest()
		key := mustSave(t, s, req)

		got, err := s.Find(key)
		if err != nil {
			t.Fatalf("Find() failed: %v", err)
		}
		got2, err := s.Find(key)
		if err != nil {
			t.Errorf("Second Find() is failed: %v", err)
		}
		if *got != *got2 {
			t.Errorf("Find() = %+v, want %+v", got, got2)
		}
	})

	t.Run("FindAndDelete は2回呼び出すとエラー", func(t *testing.T) {
		s := newFixedAuthorizeRequests(t)
		req := validAuthorizeRequest()
		key := mustSave(t, s, req)

		_, err := s.FindAndDelete(key)
		if err != nil {
			t.Fatalf("Find() failed: %v", err)
		}
		_, err = s.FindAndDelete(key)
		if !errors.Is(err, ErrAuthorizeRequestNotFound) {
			t.Errorf("FindAndDelete() must return ErrAuthorizeRequestNotFound: %v", err)
		}
	})

	t.Run("FindAndDelete の後に Find を呼び出してもエラー", func(t *testing.T) {
		s := newFixedAuthorizeRequests(t)
		req := validAuthorizeRequest()
		key := mustSave(t, s, req)

		_, err := s.FindAndDelete(key)
		if err != nil {
			t.Fatalf("Find() failed: %v", err)
		}
		_, err = s.Find(key)
		if !errors.Is(err, ErrAuthorizeRequestNotFound) {
			t.Errorf("Find() must return ErrAuthorizeRequestNotFound: %v", err)
		}
	})

	t.Run("存在しない key はエラー", func(t *testing.T) {
		s := newFixedAuthorizeRequests(t)
		req := validAuthorizeRequest()
		mustSave(t, s, req)

		_, err := s.Find("notExist")
		if !errors.Is(err, ErrAuthorizeRequestNotFound) {
			t.Errorf("Find() must return ErrAuthorizeRequestNotFound: %v", err)
		}
	})

	t.Run("存在しない key は FindAndDelete でもエラー", func(t *testing.T) {
		s := newFixedAuthorizeRequests(t)

		got, err := s.FindAndDelete("notExist")
		if !errors.Is(err, ErrAuthorizeRequestNotFound) {
			t.Errorf("FindAndDelete() error = %v, want ErrAuthorizeRequestNotFound", err)
		}
		if got != nil {
			t.Errorf("FindAndDelete() = %+v, want nil", got)
		}
	})

	t.Run("期限", func(t *testing.T) {
		lookups := []struct {
			name string
			call func(s *AuthorizeRequests, key string) (*AuthorizeRequest, error)
		}{
			{"Find", (*AuthorizeRequests).Find},
			{"FindAndDelete", (*AuthorizeRequests).FindAndDelete},
		}
		cases := []struct {
			name    string
			elapsed time.Duration
			wantErr bool
		}{
			{"直後は有効", 0, false},
			{"10 分ちょうどは有効", 10 * time.Minute, false},
			{"10 分 1 秒で失効", 10*time.Minute + time.Second, true},
		}
		for _, l := range lookups {
			for _, tc := range cases {
				t.Run(l.name+"/"+tc.name, func(t *testing.T) {
					s := newFixedAuthorizeRequests(t)
					key := mustSave(t, s, validAuthorizeRequest())
					advanceAuthorize(s, tc.elapsed)

					_, err := l.call(s, key)
					if tc.wantErr && !errors.Is(err, ErrAuthorizeRequestNotFound) {
						t.Errorf("%s() error = %v, want ErrAuthorizeRequestNotFound", l.name, err)
					}
					if !tc.wantErr && err != nil {
						t.Errorf("%s() error = %v, want nil", l.name, err)
					}
				})
			}
		}
	})

	t.Run("期限切れでも FindAndDelete は消す", func(t *testing.T) {
		s := newFixedAuthorizeRequests(t)
		key := mustSave(t, s, validAuthorizeRequest())
		advanceAuthorize(s, 11*time.Minute)

		if _, err := s.FindAndDelete(key); !errors.Is(err, ErrAuthorizeRequestNotFound) {
			t.Fatalf("expired FindAndDelete() error = %v, want ErrAuthorizeRequestNotFound", err)
		}
		advanceAuthorize(s, 0)
		if _, err := s.Find(key); !errors.Is(err, ErrAuthorizeRequestNotFound) {
			t.Errorf("Find() after expired FindAndDelete() error = %v, want ErrAuthorizeRequestNotFound", err)
		}
	})

	t.Run("Find の戻り値を書き換えてもストアは変わらない", func(t *testing.T) {
		s := newFixedAuthorizeRequests(t)
		key := mustSave(t, s, validAuthorizeRequest())

		got, err := s.Find(key)
		if err != nil {
			t.Fatalf("Find() failed: %v", err)
		}
		got.RedirectURI = "http://evil/cb"

		again, err := s.Find(key)
		if err != nil {
			t.Fatalf("second Find() failed: %v", err)
		}
		if again.RedirectURI != "http://rp/cb" {
			t.Errorf("RedirectURI = %q, want http://rp/cb", again.RedirectURI)
		}
	})

	t.Run("Save の後に引数を書き換えてもストアは変わらない", func(t *testing.T) {
		s := newFixedAuthorizeRequests(t)
		req := validAuthorizeRequest()
		key := mustSave(t, s, req)
		req.RedirectURI = "http://evil/cb"

		got, err := s.Find(key)
		if err != nil {
			t.Fatalf("Find() failed: %v", err)
		}
		if got.RedirectURI != "http://rp/cb" {
			t.Errorf("RedirectURI = %q, want http://rp/cb", got.RedirectURI)
		}
	})

	t.Run("Save は引数の ExpiresAt を書き換えない", func(t *testing.T) {
		s := newFixedAuthorizeRequests(t)
		req := validAuthorizeRequest()
		mustSave(t, s, req)

		if !req.ExpiresAt.IsZero() {
			t.Errorf("req.ExpiresAt = %v, want zero", req.ExpiresAt)
		}
	})

	t.Run("key は毎回違う 43 文字の base64url", func(t *testing.T) {
		s := newFixedAuthorizeRequests(t)
		key1 := mustSave(t, s, validAuthorizeRequest())
		key2 := mustSave(t, s, validAuthorizeRequest())

		if key1 == key2 {
			t.Errorf("Save() returned the same key twice: %s", key1)
		}
		for _, key := range []string{key1, key2} {
			if len(key) != 43 {
				t.Errorf("len(key) = %d, want 43", len(key))
			}
			if strings.ContainsAny(key, "+/=") {
				t.Errorf("key %q contains characters outside base64url", key)
			}
		}
	})

	t.Run("同時に FindAndDelete しても成功は 1 回だけ", func(t *testing.T) {
		s := newFixedAuthorizeRequests(t)
		key := mustSave(t, s, validAuthorizeRequest())

		const workers = 16
		var wg sync.WaitGroup
		var ok atomic.Int32
		start := make(chan struct{})
		for range workers {
			wg.Go(func() {
				<-start
				if _, err := s.FindAndDelete(key); err == nil {
					ok.Add(1)
				}
			})
		}
		close(start)
		wg.Wait()

		if ok.Load() != 1 {
			t.Errorf("successful FindAndDelete() = %d, want 1", ok.Load())
		}
	})
}
