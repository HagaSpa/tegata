package handler

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/HagaSpa/tegata/internal/jwt"
	"github.com/HagaSpa/tegata/internal/op/store"
)

const tokenTTL = time.Hour

type RefreshTokenOperator interface {
	Issue(clientID string, sub string, scope string) string
	Rotate(key string, clientID string) (string, *store.RefreshToken, error)
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
	client        ClientAuthenticator
	refreshTokens RefreshTokenOperator
	codes         CodeConsumer
	signer        Signer
	issuer        string
	resolver      AudienceResolver
	now           func() time.Time
}

func NewTokenHandler(
	client ClientAuthenticator,
	refreshTokens RefreshTokenOperator,
	codes CodeConsumer,
	signer Signer,
	resolver AudienceResolver,
	issuer string,
) *TokenHandler {
	return &TokenHandler{
		client:        client,
		refreshTokens: refreshTokens,
		codes:         codes,
		signer:        signer,
		issuer:        issuer,
		resolver:      resolver,
		now:           time.Now,
	}
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func (h *TokenHandler) Post(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, errInvalidRequest, "parse failed")
		return
	}

	clientID, authed := authenticateClient(w, r, h.client)
	if !authed {
		return
	}

	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		h.authorizationCode(w, r, clientID)
	case "refresh_token":
		h.refreshToken(w, r, clientID)
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

	access, err := h.signAccessToken(code.Sub, code.Scope, now)
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

	if slices.Contains(strings.Fields(code.Scope), "offline_access") {
		key := h.refreshTokens.Issue(clientID, code.Sub, code.Scope)
		v.RefreshToken = key
	}

	writeJSON(w, http.StatusOK, v)
}

func (h *TokenHandler) refreshToken(
	w http.ResponseWriter,
	r *http.Request,
	clientID string,
) {
	nextKey, next, err := h.refreshTokens.Rotate(r.PostFormValue("refresh_token"), clientID)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, errInvalidGrant, err.Error())
		return
	}

	access, err := h.signAccessToken(next.Sub, next.Scope, h.now())
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, errServerError, "failed to sign access_token")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	v := tokenResponse{
		AccessToken:  access.String(),
		TokenType:    "Bearer",
		ExpiresIn:    int64(tokenTTL.Seconds()),
		Scope:        next.Scope,
		RefreshToken: nextKey,
	}
	writeJSON(w, http.StatusOK, v)
}

func (h *TokenHandler) signAccessToken(
	sub string,
	scope string,
	now time.Time,
) (*jwt.Token, error) {
	aud := jwt.Audience{h.issuer + "/userinfo"}
	aud = append(aud, h.resolver.Audiences(scope)...)
	access, err := h.signer.Sign(&jwt.Claims{
		Iss:   h.issuer,
		Sub:   sub,
		Aud:   aud,
		Iat:   now.Unix(),
		Exp:   now.Add(tokenTTL).Unix(),
		Scope: scope,
	})
	return access, err
}
