package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters — tuned for server-side hashing (≈100ms on modern hardware).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	argonKeyLen  = 32 // 256-bit key
	saltLen      = 16 // 128-bit salt
)

// HashPassword returns a base64-encoded Argon2id hash (salt + derived key).
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	combined := make([]byte, saltLen+argonKeyLen)
	copy(combined[:saltLen], salt)
	copy(combined[saltLen:], hash)

	return base64.StdEncoding.EncodeToString(combined), nil
}

// VerifyPassword re-derives the Argon2id key and compares in constant time.
func VerifyPassword(password, storedHash string) bool {
	combined, err := base64.StdEncoding.DecodeString(storedHash)
	if err != nil || len(combined) != saltLen+argonKeyLen {
		return false
	}

	salt := combined[:saltLen]
	storedKey := combined[saltLen:]

	computedKey := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	if len(computedKey) != len(storedKey) {
		return false
	}
	var result byte
	for i := 0; i < len(computedKey); i++ {
		result |= computedKey[i] ^ storedKey[i]
	}
	return result == 0
}

// DeriveKey derives a 256-bit encryption key from a password and salt using Argon2id.
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

// EncryptContent encrypts content with AES-256-GCM using a password-derived key.
// Output format: base64(salt + nonce + ciphertext + GCM tag).
func EncryptContent(content, password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	key := DeriveKey(password, salt)

	block, err := aes.NewCipher(key)
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

	ciphertext := gcm.Seal(nonce, nonce, []byte(content), nil)

	combined := make([]byte, saltLen+len(ciphertext))
	copy(combined[:saltLen], salt)
	copy(combined[saltLen:], ciphertext)

	return base64.StdEncoding.EncodeToString(combined), nil
}

// DecryptContent reverses EncryptContent: extracts the salt, derives the key,
// and decrypts the AES-256-GCM ciphertext.
func DecryptContent(encryptedContent, password string) (string, error) {
	combined, err := base64.StdEncoding.DecodeString(encryptedContent)
	if err != nil {
		return "", err
	}

	if len(combined) < saltLen {
		return "", errors.New("invalid encrypted content")
	}

	salt := combined[:saltLen]
	ciphertext := combined[saltLen:]

	key := DeriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("invalid ciphertext")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// HashIP produces a privacy-preserving hash of an IP address.
// Uses HMAC-SHA256 with the configured secret to resist rainbow tables.
// Falls back to plain SHA-256 if no secret is set (not recommended in production).
func HashIP(ip, secret string) string {
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(ip))
		return base64.StdEncoding.EncodeToString(mac.Sum(nil))
	}
	hash := sha256.Sum256([]byte(ip))
	return base64.StdEncoding.EncodeToString(hash[:])
}
