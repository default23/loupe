package crypto

import (
	"testing"
)

func testKey() string {
	return "correct horse battery staple"
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c, err := NewCipher(testKey())
	if err != nil {
		t.Fatal(err)
	}
	type payload struct{ Secret string }
	in := payload{Secret: "hunter2"}

	blob, err := c.EncryptJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) == 0 {
		t.Fatal("empty ciphertext")
	}

	var out payload
	if err := c.DecryptJSON(blob, &out); err != nil {
		t.Fatal(err)
	}
	if out.Secret != in.Secret {
		t.Errorf("round trip mismatch: got %q", out.Secret)
	}
}

func TestWrongKeyFails(t *testing.T) {
	c1, _ := NewCipher(testKey())
	blob, _ := c1.Encrypt([]byte("data"))

	c2, _ := NewCipher("a different passphrase")
	if _, err := c2.Decrypt(blob); err == nil {
		t.Fatal("expected decrypt to fail with wrong key")
	}
}

func TestNilCipherIsErrNoKey(t *testing.T) {
	c, err := NewCipher("")
	if err != nil {
		t.Fatal(err)
	}
	if c != nil {
		t.Fatal("expected nil cipher for empty key")
	}
	if _, err := c.Encrypt([]byte("x")); err != ErrNoKey {
		t.Errorf("expected ErrNoKey, got %v", err)
	}
}

func TestArbitraryKeyAccepted(t *testing.T) {
	// Any non-empty string is a valid key; it is hashed to 32 bytes.
	c, err := NewCipher("x")
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("expected a cipher for a non-empty key")
	}
}
