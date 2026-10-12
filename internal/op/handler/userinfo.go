package handler

import (
	"net/http"
	"slices"
	"strings"

	"github.com/HagaSpa/tegata/internal/op/auth"
)

type Verifier interface {
	Verify(token string) (*auth.Claim, error)
}

type ProfileFinder interface {
	FindBySub(sub string) *auth.Profile
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
	ah := r.Header.Get("Authorization")
	if ah == "" || len(strings.Fields(ah)) != 2 {
		writeBearerChallenge(w)
		return
	}
	sl := strings.Fields(ah)
	if !strings.EqualFold(sl[0], "Bearer") {
		writeBearerChallenge(w)
		return
	}

	claim, err := h.verifier.Verify(sl[1])
	if err != nil {
		writeBearerError(w, errInvalidToken)
		return
	}
	if claim.Iss != h.issuer {
		writeBearerError(w, errInvalidToken)
		return
	}
	if claim.Aud != h.issuer+"/userinfo" {
		writeBearerError(w, errInvalidToken)
		return

	}

	user := h.finder.FindBySub(claim.Sub)
	if user == nil {
		writeBearerError(w, errInvalidToken)
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
