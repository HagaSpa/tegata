package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
)

const (
	pdkdf2Iterations = 600000
	pbkdf2KeyLen     = 32
)

var ErrInvalidCredential = errors.New("invalid credential")

type User struct {
	sub  string
	salt []byte
	hash []byte
}

type UserStore struct {
	users map[string]*User
}

func NewUserStore(seedUsername string, seedPassword string, seedSub string) (*UserStore, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("read salt: %w", err)
	}
	hash, err := pbkdf2.Key(sha256.New, seedPassword, salt, pdkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return &UserStore{
		users: map[string]*User{
			seedUsername: {
				sub:  seedSub,
				salt: salt,
				hash: hash,
			},
		},
	}, nil
}

func (s *UserStore) Authenticate(username string, password string) (string, error) {
	user := s.users[username]
	if user == nil {
		return "", ErrInvalidCredential
	}
	hash, err := pbkdf2.Key(sha256.New, password, user.salt, pdkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return "", fmt.Errorf("derive key: %w", err)
	}
	res := subtle.ConstantTimeCompare(user.hash, hash)
	if res == 1 {
		return user.sub, nil
	}
	return "", ErrInvalidCredential
}
