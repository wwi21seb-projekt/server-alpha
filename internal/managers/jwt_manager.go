package managers

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"os"
	"server-alpha/internal/schemas"
	"server-alpha/internal/utils"
	"time"
)

type JWTMgr interface {
	GenerateJWT(claims jwt.Claims) (string, error)
	ValidateJWT(tokenString string) (jwt.Claims, error)
	JWTMiddleware(next http.Handler) http.Handler
	GenerateClaims(userId, username string) jwt.Claims
}

// JWTManager handles JWT generation, signing, and validation.
type JWTManager struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// NewJWTManager creates a new JWTManager with the initial key pair.
func NewJWTManager() (JWTMgr, error) {
	privateKey, err := parsePrivateKey(os.Getenv("JWT_PRIVATE_KEY"))
	if err != nil {
		return nil, err
	}
	publicKey, err := parsePublicKey(os.Getenv("JWT_PUBLIC_KEY"))
	if err != nil {
		return nil, err
	}
	return &JWTManager{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

// parsePrivateKey parses a PEM formatted private key.
func parsePrivateKey(privKeyB64Str string) (ed25519.PrivateKey, error) {
	privKeyPemStr := fmt.Sprintf("-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----", privKeyB64Str)

	block, _ := pem.Decode([]byte(privKeyPemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	ed25519Priv, ok := priv.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid private key type, expected ed25519.PrivateKey")
	}

	return ed25519Priv, nil
}

// parsePublicKey parses a PEM formatted public key.
func parsePublicKey(pubKeyB64Str string) (ed25519.PublicKey, error) {
	pubKeyPemStr := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", pubKeyB64Str)

	block, _ := pem.Decode([]byte(pubKeyPemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ed25519Pub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key type, expected ed25519.PublicKey")
	}

	return ed25519Pub, nil
}

// GenerateClaims generates the standard JWT claims.
func (jm *JWTManager) GenerateClaims(userId, username string) jwt.Claims {
	return jwt.MapClaims{
		"iss":      "server-alpha.tech",
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
		"sub":      userId,
		"username": username,
	}
}

// GenerateJWT generates a new JWT with the given claims.
func (jm *JWTManager) GenerateJWT(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(jm.privateKey)
}

// ValidateJWT validates the given JWT and returns the claims if valid.
func (jm *JWTManager) ValidateJWT(tokenString string) (jwt.Claims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if token.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
			return nil, fmt.Errorf("invalid signing method")
		}

		return jm.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}

	return token.Claims, nil
}

func (jm *JWTManager) JWTMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		// Extract the JWT token from the request header
		header := r.Header.Get("Authorization")
		token := header[len("Bearer "):]

		// Validate the JWT token
		claims, err := jm.ValidateJWT(token)
		if err != nil {
			utils.WriteAndLogError(w, schemas.Unauthorized, http.StatusUnauthorized, err)
			return
		}

		// Add the claims to the request context
		ctx := r.Context()
		ctx = context.WithValue(ctx, "claims", claims)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
