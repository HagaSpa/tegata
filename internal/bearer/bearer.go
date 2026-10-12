package bearer

import (
	"fmt"
	"net/http"
	"strings"
)

type ErrorCode string

const InvalidToken ErrorCode = "invalid_token"

func Token(r *http.Request) (string, bool) {
	f := strings.Fields(r.Header.Get("Authorization"))
	if len(f) != 2 || !strings.EqualFold(f[0], "Bearer") {
		return "", false
	}
	return f[1], true
}

func WriteChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func WriteError(w http.ResponseWriter, code ErrorCode) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s"`, code))
	http.Error(w, string(code), http.StatusUnauthorized)
}
