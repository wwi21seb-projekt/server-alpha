package managers

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	// keySet      JWKS
	keyPairPath string
	// currentKid  string
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key.
type JWK struct {
	KID        string    `json:"kid"`
	KeyType    string    `json:"kty"`
	Algorithm  string    `json:"alg"`
	Use        string    `json:"use"`
	Curve      string    `json:"crv"`
	PublicKey  string    `json:"x"`
	Expiration time.Time `json:"expiration"`
}

// NewJWTManager creates a new JWTManager with the initial key pair.
func NewJWTManager() (JWTMgr, error) {
	path := os.Getenv("KEY_PAIR_PATH")

	// Load key pair from given path
	var privateKey ed25519.PrivateKey
	var publicKey ed25519.PublicKey

	privateKey, publicKey, err := loadKeyPair(path)
	if err != nil {
		// No key yet for initial setup, generate a new key pair
		privKey, pubKey, err := generateKeyPair(path)
		if err != nil {
			return nil, err
		}

		privateKey = privKey
		publicKey = pubKey
	}

	return &JWTManager{
		privateKey:  privateKey,
		publicKey:   publicKey,
		keyPairPath: path,
		// keySet:      keySet,
		// currentKid: currentKid,
	}, nil
}

/* Commenting out, will be implemented later
// NewJWTManager creates a new JWTManager with the initial key pair.
func NewJWTManager() (JWTMgr, error) {
	path := os.Getenv("KEY_PAIR_PATH")
	keySet, err := loadJWKS()
	if err != nil {
		return nil, err
	}

	// Load the most recent key pair as the current key pair
	var currentKid string
	var privateKey ed25519.PrivateKey
	var publicKey ed25519.PublicKey

	keySetFromFile, err := loadJWKS()
	if err != nil {
		return nil, err
	}
	keySet = keySetFromFile

	if len(keySet.Keys) == 0 {
		// Generate a new key pair if no keys are available
		prvKey, pubKey, keyID, err := generateKeyPair(keySet, path)
		if err != nil {
			return nil, err
		}

		privateKey = prvKey
		publicKey = pubKey
		currentKid = keyID
	} else {
		currentKid = keySet.Keys[len(keySet.Keys)-1].KID
	}

	return &JWTManager{
		privateKey:  privateKey,
		publicKey:   publicKey,
		keyPairPath: path,
		keySet:      keySet,
		currentKid:  currentKid,
	}, nil
}
*/

// RotateKeys rotates the JWT keys by generating a new key pair.
func (jm *JWTManager) RotateKeys() error {
	/* Commenting out, will be implemented later
	newPrivateKey, newPublicKey, keyId, err := generateKeyPair(jm.keySet, jm.keyPairPath)
	if err != nil {
		return err
	}

	// Delete the oldest key pair, since we only need to keep the most recent two
	// key pairs for validation purposes. The oldest key pair is the last element
	if len(jm.keySet.Keys) > 2 {
		jm.keySet.Keys = jm.keySet.Keys[:len(jm.keySet.Keys)-1]

		// Save the updated key set
		if err := saveJWKS(jm.keySet); err != nil {
			return err
		}
	}

	jm.privateKey = newPrivateKey
	jm.publicKey = newPublicKey
	jm.currentKid = keyId

	*/
	return nil
}

// GenerateClaims generates the standard JWT claims.
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
		// Use the key ID from the JWT header to retrieve the corresponding public key
		// keyID, ok := token.Header["kid"].(string)  // Commenting out for single-key implementation
		// if !ok || keyID != jm.currentKid {  // Commenting out for single-key implementation
		// 	return nil, fmt.Errorf("invalid key ID")  // Commenting out for single-key implementation
		// }  // Commenting out for single-key implementation

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

// generateJWK generates a new JSON Web Key and saves it to the configuration file.
func generateJWK(keySet JWKS, publicKey ed25519.PublicKey, keyId string) error {
	newKey := JWK{
		KID:        keyId,
		KeyType:    "OKP",
		Algorithm:  "EdDSA",
		Use:        "sig",
		Curve:      "Ed25519",
		PublicKey:  base64.StdEncoding.EncodeToString(publicKey),
		Expiration: time.Now().Add(time.Hour * 24 * 30), // Adjust expiration as needed
	}

	// Insert key in the beginning of the key set
	keySet.Keys = append([]JWK{newKey}, keySet.Keys...)

	// Save the updated key set
	if err := saveJWKS(keySet); err != nil {
		return err
	}

	return nil
}

// generateKID generates a Key ID based on the SHA-256 hash of the public key.
func generateKID(publicKey ed25519.PublicKey) string {
	hash := sha256.Sum256(publicKey)
	return base64.URLEncoding.EncodeToString(hash[:])
}

// saveJWKS saves the JSON Web Key Set to the configuration file.
func saveJWKS(keySet JWKS) error {
	configPath := "config.json" // Update with the actual path of your config file
	config := struct {
		Keys JWKS `json:"keys"`
	}{
		Keys: keySet,
	}
	configFile, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, configFile, 0644)
}

// loadJWKS loads the JSON Web Key Set from the configuration file.
func loadJWKS() (JWKS, error) {
	configPath := "configs/jwks-config.json" // Update with the actual path of your config file
	configFile, err := os.ReadFile(configPath)
	if err != nil {
		return JWKS{}, err
	}

	var config struct {
		Keys JWKS `json:"keys"`
	}
	err = json.Unmarshal(configFile, &config)
	if err != nil {
		return JWKS{}, err
	}

	return config.Keys, nil
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

/* Commenting out, will be implemented later
// generateKeyPair generates a new key pair and saves it to a file.
func generateKeyPair(keySet JWKS, path string) (ed25519.PrivateKey, ed25519.PublicKey, string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}

	// Generate a unique key ID based on the SHA-256 hash of the public key
	keyID := generateKID(publicKey)

	// Save the new key pair to a file for persistence
	err = saveKeyPair(privateKey, publicKey, keyID, path)
	if err != nil {
		return nil, nil, "", err
	}

	// Generate new JWT key and save it to the configuration file
	err = generateJWK(keySet, publicKey, keyID)
	if err != nil {
		return nil, nil, "", err
	}

	return privateKey, publicKey, keyID, nil
}
*/

// saveKeyPair saves the key pair to the specified file.
func saveKeyPair(privateKey ed25519.PrivateKey, publicKey ed25519.PublicKey, path string) error {
	keyPairBytes := append(privateKey, publicKey...)
	return os.WriteFile(path, keyPairBytes, 0644)
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
