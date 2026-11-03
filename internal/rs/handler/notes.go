package handler

import (
	"encoding/json"
	"net/http"

	"github.com/HagaSpa/tegata/internal/rs/store"
)

type Operator interface {
	List(sub string) []store.Note
	Add(sub string, n store.Note)
}

type NotesHandler struct {
	operator Operator
}

func NewNotesHandler(
	operator Operator,
) *NotesHandler {
	return &NotesHandler{
		operator: operator,
	}
}

func (h *NotesHandler) Get(w http.ResponseWriter, r *http.Request) {
	claims := contextClaims(r.Context())
	if claims == nil {
		writeInternalError(w)
		return
	}
	notes := h.operator.List(claims.Sub)
	if notes == nil {
		notes = make([]store.Note, 0)
	}
	writeJSON(w, http.StatusOK, notes)
}

func (h *NotesHandler) Post(w http.ResponseWriter, r *http.Request) {
	claims := contextClaims(r.Context())
	if claims == nil {
		writeInternalError(w)
		return
	}

	var note store.Note
	if err := json.NewDecoder(r.Body).Decode(&note); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if note.Text == "" {
		http.Error(w, "text is required", http.StatusBadRequest)
		return
	}

	h.operator.Add(claims.Sub, note)
	writeJSON(w, http.StatusCreated, note)
}

func writeInternalError(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		writeInternalError(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}
