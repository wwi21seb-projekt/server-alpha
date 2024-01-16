package managers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"server-alpha/internal/schemas"
	"server-alpha/internal/utils"
	"time"
)

type JWTMgr interface {
	GenerateJWT(userId, username string, isRefreshToken bool) (string, error)
	ValidateJWT(tokenString string) (jwt.Claims, error)
	JWTMiddleware(next http.Handler) http.Handler
}

// JWTManager handles JWT generation, signing, and validation.
type JWTManager struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// NewJWTManager creates a new JWTManager with the initial key pair.
func NewJWTManager(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) JWTMgr {
	log.Info("Initializing JWT manager using provided key pair...")

	JWTManager := JWTManager{
		privateKey: privateKey,
		publicKey:  publicKey,
	}

	log.Info("Initialized JWT manager using provided key pair")

	return &JWTManager
}

func NewJWTManagerFromFile() (JWTMgr, error) {
	log.Info("Initializing JWT manager using key pair from file...")
	privateKeyPath := "private_key.pem"
	publicKeyPath := "public_key.pem"

	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		err := generateAndStoreKeys(privateKeyPath, publicKeyPath)
		if err != nil {
			return nil, err
		}
	}

	// Load key pem from file into memory
	privateKeyPem, publicKeyPem, err := loadKeys(privateKeyPath, publicKeyPath)
	if err != nil {
		return nil, err
	}

	// Decode keys from pem format to ed25519 keys
	privateKey, publicKey, err := decodeKeys(privateKeyPem, publicKeyPem)
	if err != nil {
		return nil, err
	}

	log.Info("Initialized JWT manager using key pair from file")

	return &JWTManager{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

func loadKeys(privateKeyPath, publicKeyPath string) ([]byte, []byte, error) {
	log.Info("Loading key pair from file...")
	// Read the private key from file
	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Errorf("failed to read private key: %v", err)
		return nil, nil, err
	}

	// Read the public key from file
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		log.Errorf("failed to read public key: %v", err)
		return nil, nil, err
	}

	log.Info("Loaded key pair from file")
	return privateKeyBytes, publicKeyBytes, nil
}

func decodeKeys(privateKeyPem, publicKeyPem []byte) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	log.Info("Decoding key pair from PEM format...")
	// Decode the private key from PEM format
	privateKeyBlock, _ := pem.Decode(privateKeyPem)
	if privateKeyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode private key block from PEM format")
	}

	// Parse the private key
	privateKeyAny, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		log.Errorf("failed to parse private key: %v", err)
		return nil, nil, err
	}

	// Decode the public key from PEM format
	publicKeyBlock, _ := pem.Decode(publicKeyPem)
	if publicKeyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode public key block from PEM format")
	}

	// Parse the public key from the decoded PEM block
	publicKeyAny, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		log.Errorf("failed to parse public key: %v", err)
		return nil, nil, err
	}

	log.Info("Decoded key pair from PEM format")
	return privateKeyAny.(ed25519.PrivateKey), publicKeyAny.(ed25519.PublicKey), nil
}

func generateAndStoreKeys(privateKeyPath, publicKeyPath string) error {
	log.Info("Generating new key pair...")

	// Generate a new key pair if the private key does not exist
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Errorf("failed to generate key pair: %v", err)
		return err
	}

	// Save the private key
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Errorf("failed to marshal private key: %v", err)
		return err
	}

	privateBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	privateKeyFile, err := os.Create(privateKeyPath)
	if err != nil {
		log.Errorf("failed to create private key file: %v", err)
		return err
	}
	defer func(privateKeyFile *os.File) {
		err := privateKeyFile.Close()
		if err != nil {
			log.Errorf("failed to close private key file: %v", err)
		}
	}(privateKeyFile)

	err = pem.Encode(privateKeyFile, privateBlock)
	if err != nil {
		log.Errorf("failed to encode private key: %v", err)
		return err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Errorf("failed to marshal public key: %v", err)
		return err
	}

	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	publicKeyFile, err := os.Create(publicKeyPath)
	if err != nil {
		log.Errorf("failed to create public key file: %v", err)
		return err
	}

	defer func(publicKeyFile *os.File) {
		err := publicKeyFile.Close()
		if err != nil {
			log.Errorf("failed to close public key file: %v", err)
		}
	}(publicKeyFile)

	err = pem.Encode(publicKeyFile, publicBlock)
	if err != nil {
		log.Errorf("failed to encode public key: %v", err)
		return err
	}
	log.Info("Generated new key pair")
	return nil
}

// GenerateClaims generates the standard JWT claims.
func generateClaims(userId, username string, isRefreshToken bool) jwt.Claims {
	var exp int64
	var refresh string

	if isRefreshToken {
		exp = time.Now().Add(time.Hour * 24 * 7).Unix()
		refresh = "true"
	} else {
		exp = time.Now().Add(time.Hour * 24).Unix()
		refresh = "false"
	}

	return jwt.MapClaims{
		"iss":      "server-alpha.tech",
		"iat":      time.Now().Unix(),
		"exp":      exp,
		"sub":      userId,
		"username": username,
		"refresh":  refresh,
	}
}

// GenerateJWT generates a new JWT with the given claims.
func (jm *JWTManager) GenerateJWT(userId, username string, isRefreshToken bool) (string, error) {
	claims := generateClaims(userId, username, isRefreshToken)

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
		// Check if the request has a JWT token
		if r.Header.Get("Authorization") == "" {
			utils.WriteAndLogError(w, schemas.Unauthorized, http.StatusUnauthorized, fmt.Errorf("missing authorization header"))
			return
		}

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
		ctx = context.WithValue(ctx, utils.ClaimsKey, claims)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
