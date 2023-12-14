package managers

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"time"
)

type JWTMgr interface {
	GenerateJWT(claims jwt.Claims) (string, error)
	ValidateJWT(tokenString string) (jwt.Claims, error)
	RotateKeys() error
	GenerateClaims(userId string) jwt.Claims
}

// JWTManager handles JWT generation, signing, and validation.
type JWTManager struct {
	privateKey  ed25519.PrivateKey
	publicKey   ed25519.PublicKey
	keyPairPath string
}

// NewJWTManager creates a new JWTManager with the initial key pair.
func NewJWTManager() (JWTMgr, error) {
	path := os.Getenv("KEY_PAIR_PATH")
	privateKey, publicKey, err := loadKeyPair(path)

	if err != nil {
		// Generate a new key pair if it does not exist
		privateKey, publicKey, err = generateKeyPair(path)
		if err != nil {
			return nil, err
		}
	}

	return &JWTManager{privateKey, publicKey, path}, nil
}

func (jm *JWTManager) GenerateClaims(userId string) jwt.Claims {
	return jwt.MapClaims{
		"iss": "server-alpha.tech",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour * 24).Unix(),
		"sub": userId,
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
		// Use the public key from the key pair for validation
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

// RotateKeys rotates the JWT keys by generating a new key pair.
func (jm *JWTManager) RotateKeys() error {
	newPublicKey, newPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	jm.privateKey = newPrivateKey
	jm.publicKey = newPublicKey

	// Save the new key pair to a file for persistence
	err = saveKeyPair(newPrivateKey, newPublicKey, jm.keyPairPath)
	if err != nil {
		return err
	}

	return nil
}

// loadKeyPair loads the key pair from the specified file.
func loadKeyPair(path string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	keyPairBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	var privateKey ed25519.PrivateKey
	var publicKey ed25519.PublicKey

	// The key pair is the concatenation of private and public keys
	if len(keyPairBytes) == ed25519.PrivateKeySize+ed25519.PublicKeySize {
		privateKey = keyPairBytes[:ed25519.PrivateKeySize]
		publicKey = keyPairBytes[ed25519.PrivateKeySize:]
	} else {
		return nil, nil, fmt.Errorf("invalid key pair format")
	}

	return privateKey, publicKey, nil
}

// generateKeyPair generates a new key pair and saves it to a file.
func generateKeyPair(path string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Save the new key pair to a file for persistence
	err = saveKeyPair(privateKey, publicKey, path)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

// saveKeyPair saves the key pair to the specified file.
func saveKeyPair(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, path string) error {
	keyPairBytes := append(privateKey, publicKey...)

	return os.WriteFile(path, keyPairBytes, 0644)
}
