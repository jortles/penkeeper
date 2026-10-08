package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

const encPrefix = "enc:"

var encKey []byte

// Init derives a 256-bit AES key from the provided secret.
// Call once at startup before any Encrypt/Decrypt calls.
func Init(secret []byte) {
	h := sha256.Sum256(secret)
	encKey = h[:]
}

// Encrypt encrypts plaintext using AES-256-GCM and returns a prefixed
// base64 string. Returns the empty string unchanged.
func Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	if encKey == nil {
		return "", errors.New("crypto: not initialized")
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// IsEncrypted reports whether s is a value produced by Encrypt (as opposed
// to plaintext stored before encryption was enabled).
func IsEncrypted(s string) bool {
	return strings.HasPrefix(s, encPrefix)
}

// Decrypt decrypts a value produced by Encrypt. If the value does not
// carry the "enc:" prefix it is returned as-is, providing backward
// compatibility with plaintext data written before encryption was enabled.
func Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	if !strings.HasPrefix(ciphertext, encPrefix) {
		// Plaintext value from before encryption was enabled.
		return ciphertext, nil
	}
	if encKey == nil {
		return "", errors.New("crypto: not initialized")
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ciphertext, encPrefix))
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return "", errors.New("crypto: ciphertext too short")
	}

	nonce, data := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
