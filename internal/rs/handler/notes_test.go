package handler

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/HagaSpa/tegata/internal/jwt"
	"github.com/HagaSpa/tegata/internal/rs/store"
)

func notesRequest(method, body string, claims *jwt.Claims) *http.Request {
	req := httptest.NewRequest(method, "/notes", strings.NewReader(body))
	if claims == nil {
		return req
	}
	return req.WithContext(withClaims(req.Context(), claims))
}

func TestNotesHandler_Get(t *testing.T) {
	notes := store.NewNotes()
	notes.Add("u-0001", store.Note{Text: "first"})
	notes.Add("u-0002", store.Note{Text: "other"})
	h := NewNotesHandler(notes)

	tests := []struct {
		name     string
		sub      string
		wantBody string
	}{
		{
			name:     "自分のノートだけが返る",
			sub:      "u-0001",
			wantBody: `[{"text":"first"}]`,
		},
		{
			name:     "ノートがない sub は空の配列",
			sub:      "u-0003",
			wantBody: `[]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.Get(rec, notesRequest(http.MethodGet, "", &jwt.Claims{Sub: tt.sub}))
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, http.StatusOK, rec.Body.String())
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q, want = %q", got, "application/json")
			}
			if got := rec.Body.String(); got != tt.wantBody {
				t.Errorf("body = %q, want %q", got, tt.wantBody)
			}
		})
	}
}

func TestNotesHandler_Post_Success(t *testing.T) {
	notes := store.NewNotes()
	h := NewNotesHandler(notes)

	rec := httptest.NewRecorder()
	h.Post(rec, notesRequest(http.MethodPost, `{"text":"hi"}`, &jwt.Claims{Sub: "u-0001"}))
	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d (body %q)", rec.Code, http.StatusCreated, rec.Body.String())
	}
	if got, want := rec.Body.String(), `{"text":"hi"}`; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	want := []store.Note{{Text: "hi"}}
	if got := notes.List("u-0001"); !slices.Equal(got, want) {
		t.Errorf("List(u-0001) = %v, want %v", got, want)
	}
}

func TestNotesHandler_Post_Errors(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "JSON ではない", body: "not json"},
		{name: "ボディが空", body: ""},
		{name: "text が空文字", body: `{"text":""}`},
		{name: "text がない", body: `{}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notes := store.NewNotes()
			h := NewNotesHandler(notes)

			rec := httptest.NewRecorder()
			h.Post(rec, notesRequest(http.MethodPost, tt.body, &jwt.Claims{Sub: "u-0001"}))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
			if got := notes.List("u-0001"); len(got) != 0 {
				t.Errorf("List(u-0001) = %v, want empty", got)
			}
		})
	}
}

func TestNotesHandler_WithoutClaims(t *testing.T) {
	h := NewNotesHandler(store.NewNotes())

	tests := []struct {
		name    string
		handler http.HandlerFunc
		req     *http.Request
	}{
		{
			name:    "GET",
			handler: h.Get,
			req:     notesRequest(http.MethodGet, "", nil),
		},
		{
			name:    "POST",
			handler: h.Post,
			req:     notesRequest(http.MethodPost, `{"text":"hi"}`, nil),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tt.handler(rec, tt.req)
			if rec.Code != http.StatusInternalServerError {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
			}
		})
	}
}
