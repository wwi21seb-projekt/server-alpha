// Package managers orchestrates the creation, validation, and management of JSON Web Tokens (JWTs) for user authentication.
package managers

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/wwi21seb-projekt/errors-go/goerrors"
	"github.com/wwi21seb-projekt/server-alpha/internal/schemas"
	"github.com/wwi21seb-projekt/server-alpha/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	log "github.com/sirupsen/logrus"
)

// JWTMgr is an interface that outlines the contract for JWT management.
// It includes methods for generating and validating JWTs, and a middleware for handling JWTs in HTTP requests.
type JWTMgr interface {
	GenerateJWT(userId, username string, isRefreshToken bool) (string, error)
	ValidateJWT(tokenString string) (jwt.Claims, error)
	JWTMiddleware() gin.HandlerFunc
}

// JWTManager is a concrete implementation of the JWTMgr interface.
// It uses EdDSA keys for signing and validating JWTs.
type JWTManager struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// NewJWTManager initializes a new JWTManager with a provided pair of EdDSA keys.
// The keys are used for the creation and validation of JWTs.
func NewJWTManager(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey) JWTMgr {
	log.Info("Initializing JWT manager using provided key pair...")

	JWTManager := JWTManager{
		privateKey: privateKey,
		publicKey:  publicKey,
	}

	log.Info("Initialized JWT manager using provided key pair")

	return &JWTManager
}

// GenerateJWT creates a new JWT using the provided user details.
// The JWT is signed with the private key and can be used for user authentication.
func (jm *JWTManager) GenerateJWT(userId, username string, isRefreshToken bool) (string, error) {
	claims := generateClaims(userId, username, isRefreshToken)
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(jm.privateKey)
}

// ValidateJWT verifies a JWT using the public key and returns the claims if the token is valid.
// It is used to ensure that the JWT was created by this application and has not been tampered with.
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

// JWTMiddleware is an HTTP middleware that validates JWTs from the 'Authorization' header of incoming requests.
// It ensures that the JWT is valid and adds the claims to the request context for use in subsequent handlers.
func (jm *JWTManager) JWTMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, &schemas.ErrorDTO{Error: *goerrors.Unauthorized})
			return
		}
		// Validate the JWT token
		token := authHeader[len("Bearer "):]
		claims, err := jm.ValidateJWT(token)
		if err != nil || claims.(jwt.MapClaims)["refresh"] == "true" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, &schemas.ErrorDTO{Error: *goerrors.Unauthorized})
			return
		}
		// Add the claims to the request context
		c.Set(utils.ClaimsKey.String(), claims)
		c.Next()
	}
}

// NewJWTManagerFromFile creates a new JWTManager by loading EdDSA keys from specified files.
// If the keys don't exist, it generates and saves a new pair of keys.
// This function is typically used during the initialization phase of the application.
func NewJWTManagerFromFile() (JWTMgr, error) {
	log.Info("Initializing JWT manager using key pair from file...")

	keysDir := os.Getenv("KEYS_DIR")
	if keysDir == "" {
		keysDir = ".keys" // Default keys directory
	}
	privateKeyPath := keysDir + "/private_key.pem"
	publicKeyPath := keysDir + "/public_key.pem"

	log.Println("Keys directory: ", keysDir)
	log.Println("Private key path: ", privateKeyPath)
	log.Println("Public key path: ", publicKeyPath)

	// Create the keys directory if it doesn't exist
	err := os.MkdirAll(keysDir, 0700)
	if err != nil {
		log.Errorf("failed to create keys directory: %v", err)
		return nil, err
	}

	// Check if the private key exists
	if _, err := os.Stat(privateKeyPath); errors.Is(err, os.ErrNotExist) {
		// Generate a new key pair if the private key does not exist
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

// loadKeys reads the private and public key from specified files.
// These keys are used for signing and validating JWTs.
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

// decodeKeys decodes the keys from PEM format to EdDSA keys.
// The decoded keys are used for signing and validating JWTs.
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

// generateAndStoreKeys generates a new pair of EdDSA keys and stores them in specified files.
// The keys are used for signing and validating JWTs.
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
	log.Info("Generated new key pair under these paths:\n" + privateKeyPath + "\n" + publicKeyPath)
	return nil
}

// generateClaims creates the JWT claims including user-specific details and token type (access or refresh).
// The claims are used as the payload in the JWT.
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
