package handler

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/HagaSpa/tegata/internal/bearer"
	"github.com/HagaSpa/tegata/internal/jwt"
)

type claimsKey struct{}

func contextClaims(ctx context.Context) *jwt.Claims {
	claim, _ := ctx.Value(claimsKey{}).(*jwt.Claims)
	return claim
}

func withClaims(ctx context.Context, claims *jwt.Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

type AuthMiddleware struct {
	keyFor     jwt.KeyFunc
	issuer     string
	identifier string
}

func NewAuthMiddleware(
	keyFor jwt.KeyFunc,
	issuer string,
	identifier string,
) *AuthMiddleware {
	return &AuthMiddleware{
		keyFor:     keyFor,
		issuer:     issuer,
		identifier: identifier,
	}
}

func (a *AuthMiddleware) Require(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearer.Token(r)
		if !ok {
			bearer.WriteMissingToken(w)
			return
		}

		claims, err := jwt.Verify(token, a.keyFor, time.Now())
		if err != nil {
			bearer.WriteInvalidToken(w)
			return
		}
		if claims.Iss != a.issuer {
			bearer.WriteInvalidToken(w)
			return
		}
		if !claims.Aud.Contains(a.identifier) {
			bearer.WriteInvalidToken(w)
			return
		}
		if !slices.Contains(strings.Fields(claims.Scope), scope) {
			bearer.WriteInsufficientScope(w, scope)
			return
		}

		ctx := r.Context()
		ctx = withClaims(ctx, claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
