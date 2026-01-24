package crypto_test

import (
	"errors"
	"testing"

	"github.com/BLAgency/BLcrypto/crypto"
)

func TestNewCryptoService_ValidKeys(t *testing.T) {
	keys := crypto.KeyMap{
		"A": make([]byte, 32),
		"B": make([]byte, 32),
	}
	_, err := crypto.NewCryptoService(keys)
	if err != nil {
		t.Fatalf("Expected success, got: %v", err)
	}
}

func TestNewCryptoService_InvalidKeyLength(t *testing.T) {
	keys := crypto.KeyMap{
		"SHORT": []byte("12345"),
	}
	_, err := crypto.NewCryptoService(keys)
	if err == nil {
		t.Fatal("Expected error for short key")
	}

	// ПРАВИЛЬНАЯ ПРОВЕРКА:
	if !errors.Is(err, crypto.ErrInvalidKeySize) {
		t.Errorf("Expected ErrInvalidKeySize, got: %v", err)
	}
}

func TestNewCryptoService_EmptyKey(t *testing.T) {
	keys := crypto.KeyMap{
		"EMPTY": []byte{},
	}
	_, err := crypto.NewCryptoService(keys)
	if err == nil {
		t.Fatal("Expected error for empty key")
	}
}
