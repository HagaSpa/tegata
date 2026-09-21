package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
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
		return nil, errors.New("faild GenerateKey")
	}
	return &KeyManager{
		privateKey: key,
		keyID:      "key1",
	}, nil
}

func (m *KeyManager) GetJWKS() JWKS {
	pubKey := m.privateKey.PublicKey
	s256 := sha256.Sum256(pubKey.N.Bytes())
	kid := hex.EncodeToString(s256[:])
	n := base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes())
	jwk := JWK{
		Kty: "RSA", Use: "sig", Alg: "RS256", Kid: kid, N: n, E: e,
	}
	return JWKS{
		Keys: []JWK{jwk},
	}
}
