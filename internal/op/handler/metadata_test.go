package handler

import (
	"reflect"
	"testing"
)

func Test_newOpenIDConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		issuer string
		want   *openIDConfiguration
	}{
		{
			name:   "success",
			issuer: "testIssuer",
			want: &openIDConfiguration{
				Issuer:                                 "testIssuer",
				AuthorizationEndpoint:                  "testIssuer/authorize",
				TokenEndpoint:                          "testIssuer/token",
				UserinfoEndpoint:                       "testIssuer/userinfo",
				JwksUri:                                "testIssuer/.well-known/jwks.json",
				RevocationEndpoint:                     "testIssuer/revoke",
				EndSessionEndpoint:                     "testIssuer/logout",
				RequestURIParameterSupported:           false,
				ResponseTypesSupported:                 []string{"code"},
				SubjectTypesSupported:                  []string{"public"},
				IdTokenSigningAlgValuesSupported:       []string{"RS256"},
				ScopesSupported:                        []string{"openid", "notes.read", "notes.write", "offline_access", "profile", "email"},
				TokenEndpointAuthMethodsSupported:      []string{"client_secret_post", "client_secret_basic"},
				CodeChallengeMethodsSupported:          []string{"S256"},
				GrantTypesSupported:                    []string{"authorization_code", "refresh_token"},
				RevocationEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic"},
				ClaimsSupported:                        []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "name", "preferred_username", "email", "email_verified"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newOpenIDConfiguration(tt.issuer)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newOpenIDConfiguration() = %v, want %v", got, tt.want)
			}
		})
	}
}
