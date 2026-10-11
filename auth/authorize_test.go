package auth

import (
	"errors"
	"testing"
	"time"
)

func newFixedAuthorizeStore(t *testing.T) *AuthorizeRequestStore {
	t.Helper()
	s := NewAuthorizeRequestStore()
	s.now = func() time.Time { return testBase }
	return s
}

// s.now = func() time.Time { return testBase.Add(d) }

func validAuthorizaeRequest() *AuthorizeRequest {
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

func mustSave(t *testing.T, s *AuthorizeRequestStore, req *AuthorizeRequest) string {
	t.Helper()
	key, err := s.Save(req)
	if err != nil {
		t.Fatalf("faild save err = %v", err)
	}
	return key
}

func TestAuthorizeRequestStore(t *testing.T) {
	t.Run("保存した内容が取り出せる", func(t *testing.T) {
		s := newFixedAuthorizeStore(t)
		req := validAuthorizaeRequest()
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
		s := newFixedAuthorizeStore(t)
		req := validAuthorizaeRequest()
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
		s := newFixedAuthorizeStore(t)
		req := validAuthorizaeRequest()
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
		s := newFixedAuthorizeStore(t)
		req := validAuthorizaeRequest()
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
		s := newFixedAuthorizeStore(t)
		req := validAuthorizaeRequest()
		mustSave(t, s, req)

		_, err := s.Find("notExist")
		if !errors.Is(err, ErrAuthorizeRequestNotFound) {
			t.Errorf("Find() must return ErrAuthorizeRequestNotFound: %v", err)
		}
	})
}
