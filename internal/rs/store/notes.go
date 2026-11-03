package store

import (
	"sync"
)

type Note struct {
	Text string `json:"text"`
}

type Notes struct {
	mu    sync.Mutex
	notes map[string][]Note
}

func NewNotes() *Notes {
	return &Notes{
		notes: make(map[string][]Note),
	}
}

func (ns *Notes) List(sub string) []Note {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	return ns.notes[sub]
}

func (ns *Notes) Add(sub string, n Note) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.notes[sub] = append(ns.notes[sub], n)
}
