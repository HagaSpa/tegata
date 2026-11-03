package registry

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

type user struct {
	sub   string
	salt  []byte
	hash  []byte
	name  string
	email string
}

type Users struct {
	users map[string]*user
}

func NewUsers(
	seedUsername string,
	seedPassword string,
	seedSub string,
	seedName string,
	seedEmail string,
) (*Users, error) {
	salt := make([]byte, 16)
	rand.Read(salt)
	hash, err := pbkdf2.Key(sha256.New, seedPassword, salt, pdkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return &Users{
		users: map[string]*user{
			seedUsername: {
				sub:   seedSub,
				salt:  salt,
				hash:  hash,
				name:  seedName,
				email: seedEmail,
			},
		},
	}, nil
}

func (s *Users) Authenticate(username string, password string) (string, error) {
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

type Profile struct {
	Sub               string
	Name              string
	PreferredUsername string
	Email             string
}

func (s *Users) FindBySub(sub string) *Profile {
	var user Profile
	hasUser := false

	for k, v := range s.users {
		if v.sub == sub {
			if hasUser {
				return nil
			}
			user.Sub = v.sub
			user.Name = v.name
			user.PreferredUsername = k
			user.Email = v.email
			hasUser = true
		}
	}

	if !hasUser {
		return nil
	}

	return &user
}
