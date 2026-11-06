package registry

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
	"uuid"
)

func TestUsers_FindBySub(t *testing.T) {
	tests := []struct {
		name         string
		seedUsername string
		seedPassword string
		seedSub      string
		seedName     string
		seedEmail    string
		sub          string
		want         *Profile
	}{
		{
			name:         "sub が存在する場合は user が取得できる",
			seedUsername: "username",
			seedPassword: "password",
			seedSub:      "sub",
			seedName:     "name",
			seedEmail:    "haga@gmail.com",
			sub:          "sub",
			want: &Profile{
				Sub:               "sub",
				Name:              "name",
				PreferredUsername: "username",
				Email:             "haga@gmail.com",
				EmailVerified:     true,
			},
		},
		{
			name:         "sub が存在しない場合は nil",
			seedUsername: "username",
			seedPassword: "password",
			seedSub:      "sub",
			seedName:     "name",
			seedEmail:    "haga@gmail.com",
			sub:          "sub2",
			want:         nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewUsers(tt.seedUsername, tt.seedPassword, tt.seedSub, tt.seedName, tt.seedEmail)
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}
			got := s.FindBySub(tt.sub)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FindBySub() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUsers_Register(t *testing.T) {
	tests := []struct {
		name string
		info RegisterUserInfo
		want Profile
	}{
		{
			name: "登録したユーザでログインできる。email_verified は false",
			info: RegisterUserInfo{
				Username: "alice",
				Password: "correct horse battery",
				Name:     "Alice",
				Email:    "alice@example.com",
			},
			want: Profile{
				Name:              "Alice",
				PreferredUsername: "alice",
				Email:             "alice@example.com",
				EmailVerified:     false,
			},
		},
		{
			name: "name と email が空でも登録できる",
			info: RegisterUserInfo{
				Username: "bob",
				Password: "correct horse battery",
			},
			want: Profile{
				PreferredUsername: "bob",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewUsers("username", "password", "sub", "name", "haga@gmail.com")
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}
			if err := s.Register(tt.info); err != nil {
				t.Fatalf("Register() error = %v", err)
			}
			sub, err := s.Authenticate(tt.info.Username, tt.info.Password)
			if err != nil {
				t.Fatalf("Authenticate() error = %v", err)
			}
			if _, err := uuid.Parse(sub); err != nil {
				t.Errorf("sub = %q is not a UUID: %v", sub, err)
			}
			want := tt.want
			want.Sub = sub
			got := s.FindBySub(sub)
			if !reflect.DeepEqual(got, &want) {
				t.Errorf("FindBySub() = %v, want %v", got, &want)
			}
		})
	}
}

func TestUsers_Register_DuplicatedUsername(t *testing.T) {
	tests := []struct {
		name       string
		registered []RegisterUserInfo
		info       RegisterUserInfo
		password   string
	}{
		{
			name: "シードと同じ username は登録できない",
			info: RegisterUserInfo{
				Username: "username",
				Password: "another password",
			},
			password: "password",
		},
		{
			name: "既に登録済みの username は登録できない",
			registered: []RegisterUserInfo{
				{Username: "alice", Password: "correct horse battery"},
			},
			info: RegisterUserInfo{
				Username: "alice",
				Password: "another password",
			},
			password: "correct horse battery",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewUsers("username", "password", "sub", "name", "haga@gmail.com")
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}
			for _, r := range tt.registered {
				if err := s.Register(r); err != nil {
					t.Fatalf("Register() error = %v", err)
				}
			}
			if err := s.Register(tt.info); !errors.Is(err, ErrDuplicatedUsername) {
				t.Errorf("Register() error = %v, want %v", err, ErrDuplicatedUsername)
			}
			if _, err := s.Authenticate(tt.info.Username, tt.password); err != nil {
				t.Errorf("Authenticate() with the original password error = %v", err)
			}
		})
	}
}

func TestUsers_Register_Concurrent(t *testing.T) {
	s, err := NewUsers("username", "password", "sub", "name", "haga@gmail.com")
	if err != nil {
		t.Fatalf("could not construct receiver type: %v", err)
	}

	const n = 10
	errs := make([]error, n)
	var writes sync.WaitGroup
	for i := range n {
		writes.Go(func() {
			errs[i] = s.Register(RegisterUserInfo{Username: "alice", Password: "correct horse battery"})
		})
	}
	done := make(chan struct{})
	var readers sync.WaitGroup
	readers.Go(func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			if s.FindBySub("sub") == nil {
				t.Errorf("FindBySub() = nil while registering")
				return
			}
		}
	})
	readers.Go(func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			if _, err := s.Authenticate("username", "password"); err != nil {
				t.Errorf("Authenticate() error = %v while registering", err)
				return
			}
		}
	})

	writes.Wait()
	close(done)
	readers.Wait()

	succeeded := 0
	for _, err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrDuplicatedUsername):
		default:
			t.Errorf("Register() error = %v", err)
		}
	}
	if succeeded != 1 {
		t.Errorf("succeeded = %d, want 1", succeeded)
	}
}

func TestUsers_Register_AfterUnknownUsername(t *testing.T) {
	s, err := NewUsers("username", "password", "sub", "name", "haga@gmail.com")
	if err != nil {
		t.Fatalf("could not construct receiver type: %v", err)
	}
	if _, err := s.Authenticate("nobody", "password"); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("Authenticate() error = %v, want %v", err, ErrInvalidCredential)
	}

	done := make(chan error, 1)
	go func() {
		done <- s.Register(RegisterUserInfo{Username: "alice", Password: "correct horse battery"})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Register() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Register() is blocked after Authenticate() with an unknown username")
	}
}
