package mocks

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/mock"
	"net/http"
)

// MockJwtMgr defines the interface for a mock of the JWT manager.
// It includes methods for generating and validating JWTs, handling JWT middleware, and generating JWT claims.
type MockJwtMgr interface {
	GenerateJWT(claims jwt.Claims) (string, error)
	ValidateJWT(tokenString string) (jwt.Claims, error)
	JWTMiddleware(next http.Handler) http.Handler
	GenerateClaims(userId, username string) jwt.Claims
}

// MockJwtManager is a mock of the JWTManager.
// It implements MockJwtMgr and is used to simulate JWT operations in tests.
type MockJwtManager struct {
	mock.Mock
	err      error
	jwtToken string
	claims   jwt.Claims
}

// GenerateJWT returns a mock JWT string and an optional error, simulating the behavior of JWT generation in tests.
func (m *MockJwtManager) GenerateJWT(claims jwt.Claims) (string, error) {
	args := m.Called(claims)
	return args.String(0), args.Error(1)
}

// ValidateJWT returns mock JWT claims and an optional error, simulating the behavior of JWT validation in tests.
func (m *MockJwtManager) ValidateJWT(tokenString string) (jwt.Claims, error) {
	args := m.Called(tokenString)
	return args.Get(0).(jwt.Claims), args.Error(1)
}

// JWTMiddleware provides a mock middleware for handling JWT authentication in HTTP requests.
// It simulates the extraction, validation of JWT tokens, and storing of claims in the request context.
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

// GenerateClaims returns mock JWT claims based on the provided user ID and username, simulating the behavior of JWT claims generation in tests.
func (m *MockJwtManager) GenerateClaims(userId, username string) jwt.Claims {
	args := m.Called(userId, username)
	return args.Get(0).(jwt.Claims)
}
