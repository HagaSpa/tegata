package store

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func generateRandomString() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("generate rand: %w", err)
	}
	rs := base64.RawURLEncoding.EncodeToString(b)
	return rs, nil
}
