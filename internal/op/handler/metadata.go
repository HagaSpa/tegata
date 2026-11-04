package handler

import (
	"net/http"
)

type MetadataHandler struct {
	config *openIDConfiguration
}

func NewMetadataHandler(issuer string) *MetadataHandler {
	return &MetadataHandler{
		config: newOpenIDConfiguration(issuer),
	}
}

func (h *MetadataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.config)
}

type openIDConfiguration struct {
	Issuer                                 string   `json:"issuer"`
	AuthorizationEndpoint                  string   `json:"authorization_endpoint"`
	TokenEndpoint                          string   `json:"token_endpoint"`
	UserinfoEndpoint                       string   `json:"userinfo_endpoint"`
	JwksUri                                string   `json:"jwks_uri"`
	RevocationEndpoint                     string   `json:"revocation_endpoint"`
	ResponseTypesSupported                 []string `json:"response_types_supported"`
	SubjectTypesSupported                  []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported       []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                        []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported      []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported          []string `json:"code_challenge_methods_supported"`
	GrantTypesSupported                    []string `json:"grant_types_supported"`
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported"`
}

func newOpenIDConfiguration(issuer string) *openIDConfiguration {
	return &openIDConfiguration{
		Issuer:                                 issuer,
		AuthorizationEndpoint:                  issuer + "/authorize",
		TokenEndpoint:                          issuer + "/token",
		UserinfoEndpoint:                       issuer + "/userinfo",
		JwksUri:                                issuer + "/.well-known/jwks.json",
		RevocationEndpoint:                     issuer + "/revoke",
		ResponseTypesSupported:                 []string{"code"},
		SubjectTypesSupported:                  []string{"public"},
		IdTokenSigningAlgValuesSupported:       []string{"RS256"},
		ScopesSupported:                        []string{"openid", "notes.read", "notes.write", "offline_access"},
		TokenEndpointAuthMethodsSupported:      []string{"client_secret_post", "client_secret_basic"},
		CodeChallengeMethodsSupported:          []string{"S256"},
		GrantTypesSupported:                    []string{"authorization_code", "refresh_token"},
		RevocationEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic"},
	}
}
