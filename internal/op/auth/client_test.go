package auth

import "testing"

func TestClientStore_ValidateRedirectURI(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		uri      string
		want     bool
	}{
		{
			"登録済み ID と一致する URI は true",
			"tegata-sample",
			"http://localhost:9999/callback",
			true,
		},
		{
			"未登録 ID は false",
			"unknown-client-id",
			"http://localhost:9999/callback",
			false,
		},
		{
			"登録済み ID でも URI が 1 文字違えば false",
			"tegata-sample",
			"http://localhost:9999/callbac",
			false,
		},
		{
			"末尾スラッシュ違いも false",
			"tegata-sample",
			"http://localhost:9999/callback/",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewClientStore()
			got := s.ValidateRedirectURI(tt.clientID, tt.uri)
			if got != tt.want {
				t.Errorf("ValidateRjdirectURI() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClientStore_Authenticate(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		secret   string
		want     bool
	}{
		{
			"正しい secret は true",
			"tegata-sample",
			"dummy-secret",
			true,
		},
		{
			"1 文字違いは false",
			"tegata-sample",
			"dummy-secre",
			false,
		},
		{
			"未登録 ID は false",
			"unknown-client-id",
			"dummy-secret",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewClientStore()
			got := s.Authenticate(tt.clientID, tt.secret)
			if got != tt.want {
				t.Errorf("Authenticate() = %v, want %v", got, tt.want)
			}
		})
	}
}
