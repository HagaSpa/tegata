package handler

import (
	"encoding/json"
	"net/http"
	"net/url"
)

func redirectError(
	w http.ResponseWriter,
	r *http.Request,
	redirectURI string,
	errCode string,
	desc string,
	state string,
) {
	values := url.Values{}
	values.Set("error", errCode)
	values.Set("error_description", desc)
	if state != "" {
		values.Set("state", state)
	}
	redirectWith(w, r, redirectURI, values)
}

func redirectWith(
	w http.ResponseWriter,
	r *http.Request,
	redirectURI string,
	values url.Values,
) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "registered redirect_uri is invalid", http.StatusInternalServerError)
		return
	}
	q := u.Query()
	for k, vs := range values {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

type oauthErrResponse struct {
	Err  string `json:"error"`
	Desc string `json:"error_description"`
}

func oauthError(
	w http.ResponseWriter,
	status int,
	code string,
	desc string,
) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	b := oauthErrResponse{
		Err:  code,
		Desc: desc,
	}
	if err := json.NewEncoder(w).Encode(b); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
