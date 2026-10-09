package handler

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/HagaSpa/tegata/auth"
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
		bearerError(w, "")
		return
	}
	sl := strings.Fields(ah)
	if !strings.EqualFold(sl[0], "Bearer") {
		bearerError(w, "invalid_token")
		return
	}

	claim, err := h.verifier.Verify(sl[1])
	if err != nil {
		bearerError(w, "invalid_token")
		return
	}
	if claim.Iss != h.issuer {
		bearerError(w, "invalid_token")
		return
	}
	if claim.Aud != h.issuer+"/userinfo" {
		bearerError(w, "invalid_token")
		return

	}

	user := h.finder.FindBySub(claim.Sub)
	if user == nil {
		bearerError(w, "invalid_token")
		return
	}

	userInfo := &userInfoResponse{}
	userInfo.Sub = user.Sub
	if slices.Contains(strings.Fields(claim.Scope), "profile") {
		userInfo.Name = user.Name
		userInfo.PreferredUsername = user.PreferredUsername
	}
	if slices.Contains(strings.Fields(claim.Scope), "email") {
		userInfo.Email = user.Email
		userInfo.EmailVerified = new(true)
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(userInfo); err != nil {
		oauthError(w, 500, "server_error", "error occured")
		return
	}
}
