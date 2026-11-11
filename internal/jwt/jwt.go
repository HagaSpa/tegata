package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

var ErrExpired = errors.New("expired")

type Claims struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Aud      Audience `json:"aud"`
	Iat      int64    `json:"iat"`
	Exp      int64    `json:"exp"`
	Nonce    string   `json:"nonce,omitempty"`
	Scope    string   `json:"scope,omitempty"`
	AuthTime int64    `json:"auth_time,omitempty"`
}

type Token struct {
	header    string
	payload   string
	signature string
}

func (t *Token) String() string {
	return t.header + "." + t.payload + "." + t.signature
}

type KeyFunc func(kid string) (*rsa.PublicKey, error)

func Sign(key *rsa.PrivateKey, kid string, claims *Claims) (*Token, error) {
	h, err := json.Marshal(map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate header: %w", err)
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate payload: %w", err)
	}
	header := base64.RawURLEncoding.EncodeToString(h)
	payload := base64.RawURLEncoding.EncodeToString(p)
	digest := sha256.Sum256([]byte(header + "." + payload))
	s, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}
	return &Token{
		header:    header,
		payload:   payload,
		signature: base64.RawURLEncoding.EncodeToString(s),
	}, nil
}

func Verify(
	token string,
	keyFor KeyFunc,
	now time.Time,
) (*Claims, error) {
	c, err := VerifySignature(token, keyFor)
	if err != nil {
		return nil, err
	}

	if now.Unix() >= c.Exp {
		return nil, ErrExpired
	}

	return c, nil
}

func VerifySignature(token string, keyFor KeyFunc) (*Claims, error) {
	sl := strings.Split(token, ".")
	if len(sl) != 3 {
		return nil, errors.New("invalid token")
	}
	header, payload, signature := sl[0], sl[1], sl[2]

	hd, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}
	h := map[string]any{}
	if err := json.Unmarshal(hd, &h); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}
	if h["alg"] != "RS256" {
		return nil, errors.New("unsupported alg")
	}
	kid, ok := h["kid"].(string)
	if !ok {
		return nil, errors.New("kid is missing")
	}
	key, err := keyFor(kid)
	if err != nil {
		return nil, fmt.Errorf("failed to find key: %w", err)
	}

	digest := sha256.Sum256([]byte(header + "." + payload))
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return nil, fmt.Errorf("failed to verify signature: %w", err)
	}

	pd, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}
	c := Claims{}
	if err := json.Unmarshal(pd, &c); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	return &c, nil
}

type Audience []string

func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

func (a *Audience) UnmarshalJSON(data []byte) error {
	var sl []string
	err := json.Unmarshal(data, &sl)
	if err == nil {
		*a = Audience(sl)
		return nil
	}
	var s string
	err = json.Unmarshal(data, &s)
	if err == nil {
		*a = Audience{s}
		return nil
	}
	return fmt.Errorf("faild to Unmarshal Audience: %w", err)
}

func (a Audience) Contains(s string) bool {
	return slices.Contains(a, s)
}
