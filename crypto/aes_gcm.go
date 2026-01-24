package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// GCMNonceSize определяет длину nonce (вектора инициализации) для режима AES-GCM.
// Стандарт рекомендует 12 байт, но 16 байт также допустимы и используются для совместимости
// с существующими системами (например, твоим Node.js-бэкендом).
const GCMNonceSize = 16

// EncryptResult — структура для хранения результата шифрования в удобном формате.
// Все поля представлены в виде шестнадцатеричных строк (hex), что позволяет легко
// передавать их по сети или сохранять в JSON.
type EncryptResult struct {
	Encrypted string `json:"encrypted"` // Зашифрованные данные (без auth tag)
	IV        string `json:"iv"`        // Nonce (вектор инициализации)
	AuthTag   string `json:"authTag"`   // Аутентификационный тег (для проверки целостности)
}

// Encrypt шифрует открытый текст с использованием AES-GCM.
//
// Параметры:
//   - plaintext: строка, которую нужно зашифровать (в UTF-8)
//   - dataType: тип данных, определяющий, какой ключ использовать (например, "USER_EMAIL")
//
// Возвращает:
//   - *EncryptResult: указатель на структуру с зашифрованными данными в hex
//   - error: ошибка, если ключ не найден или произошла ошибка шифрования
//
// Особенности:
//   - Используется AES-256-GCM (ключ 32 байта → AES-256)
//   - Nonce генерируется криптографически безопасным генератором
//   - AuthTag автоматически вычисляется и отделяется от ciphertext
func (cs *CryptoService) Encrypt(plaintext string, dataType string) (*EncryptResult, error) {
	// Шаг 1: Получаем ключ по имени типа данных
	key, ok := cs.keys[dataType]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownDataType, dataType)
	}

	// Шаг 2: Создаём базовый AES-шифр (блоковый шифр)
	block, err := aes.NewCipher(key)
	if err != nil {
		// Теоретически невозможно при 32-байтном ключе, но проверяем
		return nil, err
	}

	// Шаг 3: Оборачиваем блочный шифр в режим GCM с заданным размером nonce
	gcm, err := cipher.NewGCMWithNonceSize(block, GCMNonceSize)
	if err != nil {
		return nil, err
	}

	// Шаг 4: Генерируем криптографически безопасный nonce (IV)
	nonce := make([]byte, GCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Шаг 5: Шифруем данные
	// Метод Seal возвращает: ciphertext + authTag (в одном байтовом срезе)
	ciphertextWithTag := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Шаг 6: Разделяем ciphertext и authTag
	// Overhead() возвращает длину authTag (обычно 16 байт для GCM)
	tagLen := gcm.Overhead()
	authTag := ciphertextWithTag[len(ciphertextWithTag)-tagLen:]
	encryptedData := ciphertextWithTag[:len(ciphertextWithTag)-tagLen]

	// Шаг 7: Кодируем всё в hex для удобства передачи/хранения
	return &EncryptResult{
		Encrypted: hex.EncodeToString(encryptedData),
		IV:        hex.EncodeToString(nonce),
		AuthTag:   hex.EncodeToString(authTag),
	}, nil
}

// Decrypt расшифровывает данные, зашифрованные с помощью AES-GCM.
//
// Параметры:
//   - encrypted: зашифрованные данные (без authTag) в виде hex-строки
//   - iv: nonce (вектор инициализации) в виде hex-строки
//   - authTag: аутентификационный тег в виде hex-строки
//   - dataType: тип данных для выбора ключа
//
// Возвращает:
//   - string: расшифрованный текст (в UTF-8)
//   - error: ошибка при неверном ключе, повреждённых данных или несовпадении authTag
//
// Важно: GCM обеспечивает **аутентифицированное шифрование** — если authTag не совпадает,
// расшифровка завершится ошибкой, и данные не будут возвращены.
func (cs *CryptoService) Decrypt(encrypted, iv, authTag, dataType string) (string, error) {
	// Шаг 1: Получаем ключ
	key, ok := cs.keys[dataType]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnknownDataType, dataType)
	}

	// Шаг 2: Декодируем hex-строки в байты
	encBytes, err := hex.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	ivBytes, err := hex.DecodeString(iv)
	if err != nil {
		return "", err
	}
	tagBytes, err := hex.DecodeString(authTag)
	if err != nil {
		return "", err
	}

	// Шаг 3: Проверяем длину nonce
	if len(ivBytes) != GCMNonceSize {
		return "", fmt.Errorf("invalid IV size: expected %d, got %d", GCMNonceSize, len(ivBytes))
	}

	// Шаг 4: Создаём AES-GCM дешифратор
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, GCMNonceSize)
	if err != nil {
		return "", err
	}

	// Шаг 5: Восстанавливаем полный шифротекст: ciphertext + authTag
	fullCiphertext := append(encBytes, tagBytes...)

	// Шаг 6: Расшифровываем и одновременно проверяем подлинность
	// Если authTag не совпадает — вернётся ошибка
	plaintext, err := gcm.Open(nil, ivBytes, fullCiphertext, nil)
	if err != nil {
		// Ошибка может быть вызвана:
		// - неправильным ключом
		// - повреждёнными данными
		// - несовпадением authTag (самая частая причина)
		return "", ErrDecryption
	}

	// Шаг 7: Преобразуем байты в строку UTF-8
	return string(plaintext), nil
}
