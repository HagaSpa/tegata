package registry

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"uuid"
)

const (
	pdkdf2Iterations = 600000
	pbkdf2KeyLen     = 32
)

var (
	ErrInvalidCredential  = errors.New("invalid credential")
	ErrDuplicatedUsername = errors.New("duplicated username")
)

type user struct {
	sub           string
	salt          []byte
	hash          []byte
	name          string
	email         string
	emailVerified bool
}

type Users struct {
	mu    sync.RWMutex
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
				sub:           seedSub,
				salt:          salt,
				hash:          hash,
				name:          seedName,
				email:         seedEmail,
				emailVerified: true,
			},
		},
	}, nil
}

func (s *Users) Authenticate(username string, password string) (string, error) {
	s.mu.RLock()
	user := s.users[username]
	s.mu.RUnlock()
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
	EmailVerified     bool
}

func (s *Users) FindBySub(sub string) *Profile {
	var user Profile
	hasUser := false

	s.mu.RLock()
	defer s.mu.RUnlock()
	for k, v := range s.users {
		if v.sub == sub {
			if hasUser {
				return nil
			}
			user.Sub = v.sub
			user.Name = v.name
			user.PreferredUsername = k
			user.Email = v.email
			user.EmailVerified = v.emailVerified
			hasUser = true
		}
	}

	if !hasUser {
		return nil
	}

	return &user
}

type RegisterUserInfo struct {
	Username string
	Password string
	Name     string
	Email    string
}

func (s *Users) Register(
	info RegisterUserInfo,
) error {
	salt := make([]byte, 16)
	rand.Read(salt)
	hash, err := pbkdf2.Key(sha256.New, info.Password, salt, pdkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	u := s.users[info.Username]
	if u != nil {
		return ErrDuplicatedUsername
	}

	sub := uuid.New().String()
	s.users[info.Username] = &user{
		sub:           sub,
		salt:          salt,
		hash:          hash,
		name:          info.Name,
		email:         info.Email,
		emailVerified: false,
	}

	return nil
}
