package handler

import (
	"net/http"
	"slices"
	"strings"

	"github.com/HagaSpa/tegata/internal/bearer"
	"github.com/HagaSpa/tegata/internal/jwt"
	"github.com/HagaSpa/tegata/internal/op/registry"
)

type Verifier interface {
	Verify(token string) (*jwt.Claims, error)
}

type ProfileFinder interface {
	FindBySub(sub string) *registry.Profile
}

type UserInfoHandler struct {
	verifier Verifier
	finder   ProfileFinder
	issuer   string
}

func NewUserInfofHandler(
	verifier Verifier,
	finder ProfileFinder,
	issuer string,
) *UserInfoHandler {
	return &UserInfoHandler{
		verifier: verifier,
		finder:   finder,
		issuer:   issuer,
	}
}

type userInfoResponse struct {
	Sub               string `json:"sub"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     *bool  `json:"email_verified,omitempty"`
}

func (h *UserInfoHandler) Get(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer.Token(r)
	if !ok {
		bearer.WriteMissingToken(w)
		return
	}

	claim, err := h.verifier.Verify(token)
	if err != nil {
		bearer.WriteInvalidToken(w)
		return
	}
	if claim.Iss != h.issuer {
		bearer.WriteInvalidToken(w)
		return
	}
	if !claim.Aud.Contains(h.issuer + "/userinfo") {
		bearer.WriteInvalidToken(w)
		return
	}

	user := h.finder.FindBySub(claim.Sub)
	if user == nil {
		bearer.WriteInvalidToken(w)
		return
	}

	v := &userInfoResponse{}
	v.Sub = user.Sub
	if slices.Contains(strings.Fields(claim.Scope), "profile") {
		v.Name = user.Name
		v.PreferredUsername = user.PreferredUsername
	}
	if slices.Contains(strings.Fields(claim.Scope), "email") {
		v.Email = user.Email
		v.EmailVerified = new(true)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, v)
}
