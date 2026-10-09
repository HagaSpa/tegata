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

type Finder interface {
	FindBySub(sub string) *auth.Profile
}

type UserInfoHandler struct {
	verifier Verifier
	finder   Finder
	issuer   string
}

func NewUserInfofHandler(
	verifier Verifier,
	finder Finder,
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

func authError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
	http.Error(w, "invalid_token", http.StatusUnauthorized)
}

func notExistsAuthError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "invalid_token", http.StatusUnauthorized)
}

func (h *UserInfoHandler) Get(w http.ResponseWriter, r *http.Request) {
	ah := r.Header.Get("Authorization")
	if ah == "" || len(strings.Fields(ah)) != 2 {
		notExistsAuthError(w)
		return
	}
	sl := strings.Fields(ah)
	if !strings.EqualFold(sl[0], "Bearer") {
		authError(w)
		return
	}

	claim, err := h.verifier.Verify(sl[1])
	if err != nil {
		authError(w)
		return
	}
	if claim.Iss != h.issuer {
		authError(w)
		return
	}
	if claim.Aud != h.issuer+"/userinfo" {
		authError(w)
		return
	}

	user := h.finder.FindBySub(claim.Sub)
	if user == nil {
		authError(w)
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
		tokenError(w, 500, "server_error", "error occured")
		return
	}
}
