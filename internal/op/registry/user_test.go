package registry

import (
	"reflect"
	"testing"
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
