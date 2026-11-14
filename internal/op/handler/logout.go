package handler

import (
	"html/template"
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
	verifier    SignatureVerifier
	validator   PostLogoutRedirectURIValidator
	session     SessionGetDeleter
	issuer      string
	logoutFile  *template.Template
	confirmFile *template.Template
}

func NewLogoutHandler(
	verifier SignatureVerifier,
	validator PostLogoutRedirectURIValidator,
	session SessionGetDeleter,
	issuer string,
) *LogoutHandler {
	lf := template.Must(template.ParseFS(htmlFS, "logout.html"))
	cf := template.Must(template.ParseFS(htmlFS, "logout_confirm.html"))
	return &LogoutHandler{
		verifier:    verifier,
		validator:   validator,
		session:     session,
		issuer:      issuer,
		logoutFile:  lf,
		confirmFile: cf,
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
		render(h.confirmFile, w, &templateParam{Error: "no exist id_token_hint"}, http.StatusBadRequest)
		return
	}

	claims, err := h.verifier.VerifySignature(hint)
	if err != nil {
		render(h.logoutFile, w, &templateParam{Error: "id_token_hint is invalid"}, http.StatusBadRequest)
		return
	}

	if claims.Iss != h.issuer {
		render(h.logoutFile, w, &templateParam{Error: "id_token_hint was not issued by this OP"}, http.StatusBadRequest)
		return
	}

	clientID := r.Form.Get("client_id")
	hasClientID := clientID != ""
	if hasClientID {
		if !claims.Aud.Contains(clientID) {
			render(h.logoutFile, w, &templateParam{Error: "client_id does not match id_token_hint"}, http.StatusBadRequest)
			return
		}
	}

	uri := r.Form.Get("post_logout_redirect_uri")
	hasURI := uri != ""
	if hasURI {
		if !h.validator.ValidatePostLogoutRedirectURI(claims.Aud[0], uri) {
			render(h.logoutFile, w, &templateParam{Error: "post_logout_redirect_uri is not registered"}, http.StatusBadRequest)
			return
		}
	}

	key, err := sessionKey(r)
	if err != nil {
		render(h.confirmFile, w, &templateParam{Error: "session_id is required"}, http.StatusBadRequest)
		return
	}

	session, err := h.session.Get(key)
	if err != nil || session.Sub != claims.Sub {
		render(h.confirmFile, w, &templateParam{Error: "invalid session_id"}, http.StatusBadRequest)
		return
	}

	h.session.Delete(key)
	clearSessionCookie(w)

	if hasURI {
		state := r.Form.Get("state")
		values := url.Values{}
		if state != "" {
			values.Set("state", state)
		}
		redirectToClient(w, r, uri, values)
		return
	}

	render(h.logoutFile, w, &templateParam{}, http.StatusOK)
}

// LogoutHandler.Post navigates to logout.html even without a session.
func (h *LogoutHandler) Post(w http.ResponseWriter, r *http.Request) {
	key, _ := sessionKey(r)

	h.session.Delete(key)
	clearSessionCookie(w)

	render(h.logoutFile, w, &templateParam{}, http.StatusOK)
}
