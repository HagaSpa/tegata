package store

import (
	"crypto/rand"
	"encoding/base64"
)

func generateRandomString() string {
	b := make([]byte, 32)
	rand.Read(b)
	rs := base64.RawURLEncoding.EncodeToString(b)
	return rs
}
