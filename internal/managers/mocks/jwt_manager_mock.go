package mocks

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/mock"
	"net/http"
)

type MockJwtMgr interface {
	GenerateJWT(claims jwt.Claims) (string, error)
	ValidateJWT(tokenString string) (jwt.Claims, error)
	JWTMiddleware(next http.Handler) http.Handler
	GenerateClaims(userId, username string) jwt.Claims
}

type MockJwtManager struct {
	mock.Mock
	err      error
	jwtToken string
	claims   jwt.Claims
}

func (m *MockJwtManager) GenerateJWT(claims jwt.Claims) (string, error) {
	args := m.Called(claims)
	return args.String(0), args.Error(1)
}

func (m *MockJwtManager) ValidateJWT(tokenString string) (jwt.Claims, error) {
	args := m.Called(tokenString)
	return args.Get(0).(jwt.Claims), args.Error(1)
}

func (m *MockJwtManager) JWTMiddleware(next http.Handler) http.Handler {
	type claimsKey string

	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the JWT token from the request header
		header := r.Header.Get("Authorization")
		token := header[len("Bearer "):]

		// Simulate JWT validation
		if m.err != nil || token != m.jwtToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Simulate claims storage in the context
		ctx := r.Context()
		ctx = context.WithValue(ctx, claimsKey("claims"), m.claims)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})

	return fn
}

func (m *MockJwtManager) GenerateClaims(userId, username string) jwt.Claims {
	args := m.Called(userId, username)
	return args.Get(0).(jwt.Claims)
}
