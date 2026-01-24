package crypto_test

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/BLAgency/BLcrypto/crypto"
)

// Helper: encrypt with AES-CBC + PKCS7 for test simulation
func encryptCBC(plaintext string, key, iv []byte) string {
	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	copy(ciphertext, padded)
	block, _ := aes.NewCipher(key)
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext, ciphertext)
	return hex.EncodeToString(ciphertext)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

func TestCBC_DecryptFront_Success(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	for i := range iv {
		iv[i] = byte(i)
	}

	cs, _ := crypto.NewCryptoService(crypto.KeyMap{"FRONT_KEY_1": key})

	payload := `{"userId":42,"action":"login"}`
	encryptedHex := encryptCBC(payload, key, iv)
	ivHex := hex.EncodeToString(iv)

	result, err := cs.DecryptFrontCBC(encryptedHex, ivHex, "FRONT_KEY_1")
	if err != nil {
		t.Fatalf("DecryptFrontCBC failed: %v", err)
	}

	if userId, ok := result["userId"].(float64); !ok || int(userId) != 42 {
		t.Errorf("Expected userId=42, got %+v", result)
	}
}

func TestCBC_InvalidPadding(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	cs, _ := crypto.NewCryptoService(crypto.KeyMap{"FRONT_KEY_1": key})

	// Invalid padding: all zeros
	invalidEnc := "00000000000000000000000000000000"
	ivHex := hex.EncodeToString(iv)

	_, err := cs.DecryptFrontCBC(invalidEnc, ivHex, "FRONT_KEY_1")
	if err == nil {
		t.Fatal("Expected error due to invalid padding")
	}
}
