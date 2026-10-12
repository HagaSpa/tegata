package auth

import (
	"reflect"
	"testing"
)

func TestUserStore_FindBySub(t *testing.T) {
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
			s, err := NewUserStore(tt.seedUsername, tt.seedPassword, tt.seedSub, tt.seedName, tt.seedEmail)
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
