package handler

import (
	"encoding/json"
	"fmt"
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
	w.Header().Set("Cache-Control", "no-store")
	v := oauthErrResponse{
		Err:  code,
		Desc: desc,
	}
	writeJSON(w, status, v)
}

func bearerError(w http.ResponseWriter, code string) {
	if code == "" {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer error=%s", code))
	} else {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	http.Error(w, "invalid_token", http.StatusUnauthorized)
}

func internalError(w http.ResponseWriter) {
	http.Error(w, "internal_server_error", http.StatusInternalServerError)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	b, err := json.Marshal(v)
	if err != nil {
		internalError(w)
		return
	}
	w.WriteHeader(status)
	w.Write(b)
}
