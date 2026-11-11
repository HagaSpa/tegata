package registry

import (
	"testing"
)

func TestClients_ValidateRedirectURI(t *testing.T) {
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
			s := NewClients()
			got := s.ValidateRedirectURI(tt.clientID, tt.uri)
			if got != tt.want {
				t.Errorf("ValidateRjdirectURI() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClients_Authenticate(t *testing.T) {
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
			s := NewClients()
			got := s.Authenticate(tt.clientID, tt.secret)
			if got != tt.want {
				t.Errorf("Authenticate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClients_ValidatePostLogoutRedirectURI(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		uri      string
		want     bool
	}{
		{
			name:     "登録された URI に完全一致",
			clientID: "conformance",
			uri:      "https://localhost.emobix.co.uk:8443/test/a/tegata/post_logout_redirect",
			want:     true,
		},
		{
			name:     "登録された URI にクエリパラメータを足した場合",
			clientID: "conformance",
			uri:      "https://localhost.emobix.co.uk:8443/test/a/tegata/post_logout_redirect?foo=bar",
			want:     false,
		},
		{
			name:     "ログイン用の RedirectURI は、ログアウトでは使わせない",
			clientID: "conformance",
			uri:      "https://localhost.emobix.co.uk:8443/test/a/tegata/callback",
			want:     false,
		},
		{
			name:     "登録されていない clientID",
			clientID: "noExistID",
			uri:      "https://localhost.emobix.co.uk:8443/test/a/tegata/post_logout_redirect",
			want:     false,
		},
		{
			name:     "URI を登録していないクライアント",
			clientID: "tegata-sample",
			uri:      "https://localhost.emobix.co.uk:8443/test/a/tegata/post_logout_redirect",
			want:     false,
		},
		{
			name:     "uri が空の場合",
			clientID: "conformance",
			uri:      "",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewClients()
			got := s.ValidatePostLogoutRedirectURI(tt.clientID, tt.uri)
			if got != tt.want {
				t.Errorf("ValidatePostLogoutRedirectURI() = %v, want %v", got, tt.want)
			}
		})
	}
}
