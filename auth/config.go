package auth

type OpenIdConfiguration struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	JwksUri                          string   `json:"jwks_uri"`
	ResponseTypesSupport             []string `json:"response_types_support"`
	SubjectTypesSupport              []string `json:"subject_types_support"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
}

func NewOpenIdConfiguration(issuer string) *OpenIdConfiguration {
	return &OpenIdConfiguration{
		Issuer:                           issuer,
		AuthorizationEndpoint:            issuer + "/authorize",
		TokenEndpoint:                    issuer + "/token",
		UserinfoEndpoint:                 issuer + "/userinfo",
		JwksUri:                          issuer + "/.well-known/jwks.json",
		ResponseTypesSupport:             []string{"code"},
		SubjectTypesSupport:              []string{"public"},
		IdTokenSigningAlgValuesSupported: []string{"RS256"},
		CodeChallengeMethodsSupported:    []string{"S256"},
	}
}
