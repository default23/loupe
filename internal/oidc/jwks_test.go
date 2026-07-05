package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
)

func TestParseJWKS(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	doc, _ := json.Marshal(jwksDoc(&key.PublicKey, "k1"))

	keys, err := ParseJWKS(string(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	k := keys[0]
	if k.Kid != "k1" || k.Kty != "RSA" || k.Alg != "RS256" || k.Use != "sig" {
		t.Errorf("unexpected key summary: %+v", k)
	}
	if k.Bits != 2048 {
		t.Errorf("Bits = %d, want 2048", k.Bits)
	}
	if k.Thumbprint == "" {
		t.Error("expected a computed thumbprint")
	}
}

func TestParseJWKSErrors(t *testing.T) {
	if _, err := ParseJWKS("not json"); err == nil {
		t.Error("expected error for invalid JSON")
	}
	if _, err := ParseJWKS(`{"keys":[]}`); err == nil {
		t.Error("expected error for empty key set")
	}
}
