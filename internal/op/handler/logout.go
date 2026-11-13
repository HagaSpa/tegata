package handler

import (
	"net/http"
	"net/url"

	"github.com/HagaSpa/tegata/internal/jwt"
	"github.com/HagaSpa/tegata/internal/op/store"
)

type SignatureVerifier interface {
	VerifySignature(token string) (*jwt.Claims, error)
}

type PostLogoutRedirectURIValidator interface {
	ValidatePostLogoutRedirectURI(clientID string, uri string) bool
}

type SessionGetDeleter interface {
	Get(key string) (*store.Session, error)
	Delete(key string)
}

type LogoutHandler struct {
	verifier  SignatureVerifier
	validator PostLogoutRedirectURIValidator
	session   SessionGetDeleter
	issuer    string
}

func NewLogoutHandler(
	verifier SignatureVerifier,
	validator PostLogoutRedirectURIValidator,
	session SessionGetDeleter,
	issuer string,
) *LogoutHandler {
	return &LogoutHandler{
		verifier:  verifier,
		validator: validator,
		session:   session,
		issuer:    issuer,
	}
}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "invalid values in form", http.StatusBadRequest)
		return
	}

	hint := r.Form.Get("id_token_hint")
	if hint == "" {
		http.Error(w, "no exist id_token_hint", http.StatusBadRequest)
		return
	}

	claims, err := h.verifier.VerifySignature(hint)
	if err != nil {
		http.Error(w, "invalid id_token_hint", http.StatusBadRequest)
		return
	}

	if claims.Iss != h.issuer {
		http.Error(w, "invalid id_token_hint", http.StatusBadRequest)
		return
	}

	uri := r.Form.Get("post_logout_redirect_uri")
	hasURI := uri != ""
	if hasURI {
		if !h.validator.ValidatePostLogoutRedirectURI(claims.Aud[0], uri) {
			http.Error(w, "invalid post_logout_redirect_uri", http.StatusBadRequest)
			return
		}
	}

	cookie, err := r.Cookie("session_id")
	if err != nil {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}

	key := cookie.Value
	session, err := h.session.Get(key)
	if err != nil || session.Sub != claims.Sub {
		http.Error(w, "invalid session_id", http.StatusBadRequest)
		return
	}

	h.session.Delete(key)
	http.SetCookie(w, &http.Cookie{Name: "session_id", Value: "", MaxAge: -1, HttpOnly: true, Path: "/"})

	if hasURI {
		state := r.Form.Get("state")
		values := url.Values{}
		if state != "" {
			values.Set("state", state)
		}
		redirectToClient(w, r, uri, values)
		return
	}

	http.Error(w, "", http.StatusBadRequest)
}
