package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/HagaSpa/tegata/internal/jwt"
)

var ErrUnknownKey = errors.New("unknown key")

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

type Manager struct {
	privateKey *rsa.PrivateKey
	keyID      string
	now        func() time.Time
}

func NewManager() (*Manager, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	hash := sha256.Sum256(key.PublicKey.N.Bytes())
	keyID := hex.EncodeToString(hash[:])
	return &Manager{
		privateKey: key,
		keyID:      keyID,
		now:        time.Now,
	}, nil
}

func (m *Manager) JWKS() JWKS {
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

func (m *Manager) Sign(claims *jwt.Claims) (*jwt.Token, error) {
	return jwt.Sign(m.privateKey, m.keyID, claims)
}

func (m *Manager) Verify(token string) (*jwt.Claims, error) {
	return jwt.Verify(token, m.publicKey, m.now())
}

func (m *Manager) publicKey(kid string) (*rsa.PublicKey, error) {
	if kid != m.keyID {
		return nil, ErrUnknownKey
	}
	return &m.privateKey.PublicKey, nil
}
