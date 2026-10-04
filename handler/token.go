package handler

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/HagaSpa/tegata/auth"
)

const tokenTTL = time.Hour

type ClientAuthenticator interface {
	Authenticate(clientID, secret string) bool
}

type CodeConsumer interface {
	Consume(code string) (*auth.Code, error)
}

type Signer interface {
	Sign(*auth.Claim) (*auth.JWT, error)
}

type TokenHandler struct {
	client ClientAuthenticator
	codes  CodeConsumer
	signer Signer
	issuer string
	now    func() time.Time
}

func NewTokenHandler(
	client ClientAuthenticator,
	codes CodeConsumer,
	signer Signer,
	issuer string,
) *TokenHandler {
	return &TokenHandler{
		client: client,
		codes:  codes,
		signer: signer,
		issuer: issuer,
		now:    time.Now,
	}
}

type successResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

func (h *TokenHandler) Post(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, 400, "invalid_request", "parse failed")
		return
	}

	user, pass, ok := r.BasicAuth()
	if !ok {
		user = r.PostFormValue("client_id")
		pass = r.PostFormValue("client_secret")
	}
	if !h.client.Authenticate(user, pass) {
		if ok {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"tegata\"")
		}
		tokenError(w, 401, "invalid_client", "client_id or client_secret is invalid")
		return
	}

	if r.PostFormValue("grant_type") != "authorization_code" {
		tokenError(w, 400, "unsupported_grant_type", "grant_type is unsupported")
		return
	}

	code, err := h.codes.Consume(r.PostFormValue("code"))
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCode) {
			tokenError(w, 400, "invalid_grant", "code is invalid")
			return
		} else {
			tokenError(w, 500, "server_error", "error occured")
			return
		}
	}
	if code.ClientID != user {
		tokenError(w, 400, "invalid_grant", "client_id is invalid")
		return
	}
	if code.RedirectURI != r.PostFormValue("redirect_uri") {
		tokenError(w, 400, "invalid_grant", "redirect_uri is invalid")
		return
	}

	now := h.now()
	v := r.PostFormValue("code_verifier")
	sum := sha256.Sum256([]byte(v))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(code.CodeChallenge)) != 1 {
		tokenError(w, 400, "invalid_grant", "code_verifier is invalid")
		return
	}

	idToken, err := h.signer.Sign(&auth.Claim{
		Iss:   h.issuer,
		Sub:   code.Sub,
		Aud:   user,
		Iat:   now.Unix(),
		Exp:   now.Add(tokenTTL).Unix(),
		Nonce: code.Nonce,
	})
	if err != nil {
		tokenError(w, 500, "server_error", "error occured")
		return
	}
	access, err := h.signer.Sign(&auth.Claim{
		Iss:   h.issuer,
		Sub:   code.Sub,
		Aud:   h.issuer + "/userinfo",
		Iat:   now.Unix(),
		Exp:   now.Add(tokenTTL).Unix(),
		Scope: code.Scope,
	})
	if err != nil {
		tokenError(w, 500, "server_error", "error occured")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	b := successResponse{
		AccessToken: access.String(),
		TokenType:   "Bearer",
		ExpiresIn:   int64(tokenTTL.Seconds()),
		IDToken:     idToken.String(),
		Scope:       code.Scope,
	}
	if err := json.NewEncoder(w).Encode(b); err != nil {
		tokenError(w, 500, "server_error", "error occured")
		return
	}
}

type errResponse struct {
	Err  string `json:"error"`
	Desc string `json:"error_description"`
}

func tokenError(
	w http.ResponseWriter,
	status int,
	code string,
	desc string,
) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	b := errResponse{
		Err:  code,
		Desc: desc,
	}
	if err := json.NewEncoder(w).Encode(b); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
