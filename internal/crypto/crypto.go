// Package crypto provides AES-256-GCM encryption of secrets at rest and
// generation of self-signed SP certificates for SAML.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrNoKey is returned when a secret operation is attempted without a master key.
var ErrNoKey = errors.New("crypto: no master key configured (set MASTER_KEY)")

// Cipher encrypts and decrypts secret blobs using AES-256-GCM.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher builds a Cipher from an arbitrary master key string. The string is
// hashed with SHA-256 to derive the 32-byte AES-256 key, so any passphrase is
// accepted. If key is empty it returns a nil Cipher and no error; callers must
// treat a nil Cipher as "secrets unavailable" and surface ErrNoKey when secrets
// are needed.
func NewCipher(key string) (*Cipher, error) {
	if key == "" {
		return nil, nil
	}
	sum := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt seals plaintext, prepending a random nonce.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrNoKey
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt opens a blob produced by Encrypt.
func (c *Cipher) Decrypt(blob []byte) ([]byte, error) {
	if c == nil {
		return nil, ErrNoKey
	}
	ns := c.aead.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("crypto: ciphertext too short")
	}
	nonce, ct := blob[:ns], blob[ns:]
	pt, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt failed (wrong master key?): %w", err)
	}
	return pt, nil
}

// EncryptJSON marshals v and encrypts it. Returns nil for a nil/empty value
// when no cipher is configured only if v marshals to an empty object.
func (c *Cipher) EncryptJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return c.Encrypt(b)
}

// DecryptJSON decrypts blob and unmarshals into v. A nil/empty blob is a no-op.
func (c *Cipher) DecryptJSON(blob []byte, v any) error {
	if len(blob) == 0 {
		return nil
	}
	b, err := c.Decrypt(blob)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
