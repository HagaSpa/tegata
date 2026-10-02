package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type Claim struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Aud   string `json:"aug"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
	Nonce string `json:"nonce,omitempty"`
	Scope string `json:"scole,omitempty"`
}

type JWT struct {
	header    string
	payload   string
	signature string
}

func (m *KeyManager) Sign(claim *Claim) (*JWT, error) {
	h, err := json.Marshal(map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": m.keyID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed generate header: %v", err)
	}
	p, err := json.Marshal(claim)
	if err != nil {
		return nil, fmt.Errorf("failed generate payload: %v", err)
	}
	header := base64.RawURLEncoding.EncodeToString(h)
	payload := base64.RawURLEncoding.EncodeToString(p)
	digest := sha256.Sum256([]byte(header + "." + payload))
	s, err := rsa.SignPKCS1v15(rand.Reader, m.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return nil, fmt.Errorf("fadild generate singed: %v", err)
	}
	signature := base64.RawURLEncoding.EncodeToString(s)
	return &JWT{
		header:    header,
		payload:   payload,
		signature: signature,
	}, nil
}

func (j *JWT) String() string {
	return j.header + "." + j.payload + "." + j.signature
}
