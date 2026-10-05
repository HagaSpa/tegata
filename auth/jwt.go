package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var ErrExpired = errors.New("expired")

type Claim struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Aud   string `json:"aud"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
	Nonce string `json:"nonce,omitempty"`
	Scope string `json:"scope,omitempty"`
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
		return nil, fmt.Errorf("failed to generate header: %w", err)
	}
	p, err := json.Marshal(claim)
	if err != nil {
		return nil, fmt.Errorf("failed generate payload: %w", err)
	}
	header := base64.RawURLEncoding.EncodeToString(h)
	payload := base64.RawURLEncoding.EncodeToString(p)
	digest := sha256.Sum256([]byte(header + "." + payload))
	s, err := rsa.SignPKCS1v15(rand.Reader, m.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return nil, fmt.Errorf("fadild generate singed: %w", err)
	}
	signature := base64.RawURLEncoding.EncodeToString(s)
	return &JWT{
		header:    header,
		payload:   payload,
		signature: signature,
	}, nil
}

func (m *KeyManager) Verify(token string) (*Claim, error) {
	sl := strings.Split(token, ".")
	header := sl[0]
	payload := sl[1]
	signature := sl[2]

	hd, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil, fmt.Errorf("failed decode header: %w", err)
	}
	h := map[string]any{}
	if err = json.Unmarshal(hd, &h); err != nil {
		return nil, fmt.Errorf("Unmarshal failed: %w", err)
	}
	if h["alg"] != "RS256" {
		return nil, fmt.Errorf("invalid alg format: %w", err)
	}
	if h["kid"] != m.JWKS().Keys[0].Kid {
		return nil, fmt.Errorf("kid is not KeyManager.GetJWKS().Keys[0].kid")
	}

	digest := sha256.Sum256([]byte(header + "." + payload))
	dec, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return nil, fmt.Errorf("Decode failed: %w", err)
	}
	if err = rsa.VerifyPKCS1v15(&m.privateKey.PublicKey, crypto.SHA256, digest[:], dec); err != nil {
		return nil, fmt.Errorf("Verify failed: %w", err)
	}

	pd, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed decode payload: %w", err)
	}
	c := Claim{}
	if err = json.Unmarshal(pd, &c); err != nil {
		return nil, fmt.Errorf("Unmarshal failed: %w", err)
	}
	if m.now().Unix() >= c.Exp {
		return nil, ErrExpired
	}

	return &c, nil
}

func (j *JWT) String() string {
	return j.header + "." + j.payload + "." + j.signature
}
