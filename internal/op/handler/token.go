package handler

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/HagaSpa/tegata/internal/jwt"
	"github.com/HagaSpa/tegata/internal/op/store"
)

const tokenTTL = time.Hour

type ClientAuthenticator interface {
	Authenticate(clientID, secret string) bool
}

type CodeConsumer interface {
	Consume(code string) (*store.Code, error)
}

type Signer interface {
	Sign(*jwt.Claims) (*jwt.Token, error)
}

type AudienceResolver interface {
	Audiences(scope string) []string
}

type TokenHandler struct {
	client   ClientAuthenticator
	codes    CodeConsumer
	signer   Signer
	issuer   string
	resolver AudienceResolver
	now      func() time.Time
}

func NewTokenHandler(
	client ClientAuthenticator,
	codes CodeConsumer,
	signer Signer,
	resolver AudienceResolver,
	issuer string,
) *TokenHandler {
	return &TokenHandler{
		client:   client,
		codes:    codes,
		signer:   signer,
		issuer:   issuer,
		resolver: resolver,
		now:      time.Now,
	}
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

func (h *TokenHandler) Post(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, errInvalidRequest, "parse failed")
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
		writeTokenError(w, http.StatusUnauthorized, errInvalidClient, "client_id or client_secret is invalid")
		return
	}

	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		h.authorizationCode(w, r, user)
	default:
		writeTokenError(w, http.StatusBadRequest, errUnsupportedGrantType, "grant_type is unsupported")
	}
}

func (h *TokenHandler) authorizationCode(
	w http.ResponseWriter,
	r *http.Request,
	clientID string,
) {
	code, err := h.codes.Consume(r.PostFormValue("code"))
	if err != nil {
		if errors.Is(err, store.ErrInvalidCode) {
			writeTokenError(w, http.StatusBadRequest, errInvalidGrant, "code is invalid")
			return
		}
		writeTokenError(w, http.StatusInternalServerError, errServerError, "failed to consume code")
		return
	}
	if code.ClientID != clientID {
		writeTokenError(w, http.StatusBadRequest, errInvalidGrant, "client_id is invalid")
		return
	}
	if code.RedirectURI != r.PostFormValue("redirect_uri") {
		writeTokenError(w, http.StatusBadRequest, errInvalidGrant, "redirect_uri is invalid")
		return
	}

	now := h.now()
	sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(code.CodeChallenge)) != 1 {
		writeTokenError(w, http.StatusBadRequest, errInvalidGrant, "code_verifier is invalid")
		return
	}

	idToken, err := h.signer.Sign(&jwt.Claims{
		Iss:   h.issuer,
		Sub:   code.Sub,
		Aud:   jwt.Audience{clientID},
		Iat:   now.Unix(),
		Exp:   now.Add(tokenTTL).Unix(),
		Nonce: code.Nonce,
	})
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, errServerError, "failed to sign id_token")
		return
	}

	aud := jwt.Audience{h.issuer + "/userinfo"}
	aud = append(aud, h.resolver.Audiences(code.Scope)...)
	access, err := h.signer.Sign(&jwt.Claims{
		Iss:   h.issuer,
		Sub:   code.Sub,
		Aud:   aud,
		Iat:   now.Unix(),
		Exp:   now.Add(tokenTTL).Unix(),
		Scope: code.Scope,
	})
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, errServerError, "failed to sign access_token")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	v := tokenResponse{
		AccessToken: access.String(),
		TokenType:   "Bearer",
		ExpiresIn:   int64(tokenTTL.Seconds()),
		IDToken:     idToken.String(),
		Scope:       code.Scope,
	}
	writeJSON(w, http.StatusOK, v)
}
