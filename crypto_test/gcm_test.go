package crypto_test

import (
	"testing"

	"github.com/BLAgency/BLcrypto/crypto"
)

func TestGCM_EncryptDecrypt_Success(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	cs, err := crypto.NewCryptoService(crypto.KeyMap{"EMAIL": key})
	if err != nil {
		t.Fatalf("NewCryptoService failed: %v", err)
	}

	plaintext := "user@example.com"
	enc, err := cs.Encrypt(plaintext, "EMAIL")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if enc.Encrypted == "" || enc.IV == "" || enc.AuthTag == "" {
		t.Fatal("Encrypt returned empty fields")
	}

	dec, err := cs.Decrypt(enc.Encrypted, enc.IV, enc.AuthTag, "EMAIL")
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if dec != plaintext {
		t.Errorf("Expected %q, got %q", plaintext, dec)
	}
}

func TestGCM_Decrypt_WithTamperedData(t *testing.T) {
	key := make([]byte, 32)
	cs, _ := crypto.NewCryptoService(crypto.KeyMap{"TEST": key})

	enc, _ := cs.Encrypt("hello", "TEST")

	// Tamper with auth tag
	badTag := enc.AuthTag[:len(enc.AuthTag)-1] + "0"

	_, err := cs.Decrypt(enc.Encrypted, enc.IV, badTag, "TEST")
	if err == nil {
		t.Fatal("Expected decryption to fail with tampered auth tag")
	}
	if err != crypto.ErrDecryption {
		t.Errorf("Expected ErrDecryption, got: %v", err)
	}
}

func TestGCM_UnknownDataType(t *testing.T) {
	key := make([]byte, 32)
	cs, _ := crypto.NewCryptoService(crypto.KeyMap{"KNOWN": key})

	_, err := cs.Encrypt("test", "UNKNOWN")
	if err == nil {
		t.Fatal("Expected error for unknown data type")
	}
}
