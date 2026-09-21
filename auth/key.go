package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

// JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type KeyManager struct {
	privateKey *rsa.PrivateKey
	keyID      string
}

func NewKeyManager() (*KeyManager, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	hash := sha256.Sum256(key.PublicKey.N.Bytes())
	keyID := hex.EncodeToString(hash[:])
	return &KeyManager{
		privateKey: key,
		keyID:      keyID,
	}, nil
}

func (m *KeyManager) GetJWKS() JWKS {
	pubKey := m.privateKey.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes())
	jwk := JWK{
		Kty: "RSA", Use: "sig", Alg: "RS256", Kid: m.keyID, N: n, E: e,
	}
	return JWKS{
		Keys: []JWK{jwk},
	}
}
