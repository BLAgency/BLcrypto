package crypto_test

import (
	"testing"

	"github.com/BLAgency/BLcrypto/crypto"
)

func TestHashData_Deterministic(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 3)
	}

	cs, _ := crypto.NewCryptoService(crypto.KeyMap{
		"USER_NAME": key,
		"API_KEY":   key,
	})

	hash1, err := cs.HashData("Alice", "USER_NAME")
	if err != nil {
		t.Fatalf("HashData failed: %v", err)
	}

	hash2, _ := cs.HashData("Alice", "USER_NAME")
	if hash1 != hash2 {
		t.Error("Hash is not deterministic")
	}

	// Different input → different hash
	hash3, _ := cs.HashData("Bob", "USER_NAME")
	if hash1 == hash3 {
		t.Error("Different inputs produced same hash")
	}
}

func TestHashData_UnknownType(t *testing.T) {
	key := make([]byte, 32)
	cs, _ := crypto.NewCryptoService(crypto.KeyMap{"EXISTING": key})

	_, err := cs.HashData("test", "NONEXISTENT")
	if err == nil {
		t.Fatal("Expected error for unknown hash type")
	}
}

func TestHashData_MissingKey(t *testing.T) {
	key := make([]byte, 32)
	cs, _ := crypto.NewCryptoService(crypto.KeyMap{"OTHER": key})

	_, err := cs.HashData("test", "USER_NAME") // key not provided
	if err == nil {
		t.Fatal("Expected error for missing key")
	}
}
