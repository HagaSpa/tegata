package bearer

import (
	"fmt"
	"net/http"
	"strings"
)

type ErrorCode string

const (
	invalidToken      ErrorCode = "invalid_token"
	insufficientScope ErrorCode = "insufficient_scope"

	challengeHeader string = "WWW-Authenticate"
)

func Token(r *http.Request) (string, bool) {
	f := strings.Fields(r.Header.Get("Authorization"))
	if len(f) != 2 || !strings.EqualFold(f[0], "Bearer") {
		return "", false
	}
	return f[1], true
}

func WriteMissingToken(w http.ResponseWriter) {
	w.Header().Set(challengeHeader, "Bearer")
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func WriteInvalidToken(w http.ResponseWriter) {
	challenge := fmt.Sprintf(`Bearer error="%s"`, invalidToken)
	w.Header().Set(challengeHeader, challenge)
	http.Error(w, string(invalidToken), http.StatusUnauthorized)
}

func WriteInsufficientScope(w http.ResponseWriter, scope string) {
	challenge := fmt.Sprintf(`Bearer error="%s", scope="%s"`, insufficientScope, scope)
	w.Header().Set(challengeHeader, challenge)
	http.Error(w, string(insufficientScope), http.StatusForbidden)
}
