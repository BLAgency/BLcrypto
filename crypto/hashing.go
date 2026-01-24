package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
)

// hashSha256 вычисляет хеш SHA-256 от строки и возвращает его в виде hex-строки.
// Аналог crypto.createHash('sha256').digest('hex') в Node.js.
func hashSha256(text string) string {
	// Sum256 возвращает [32]byte — фиксированный массив
	h := sha256.Sum256([]byte(text))
	// [:] преобразует массив в срез, чтобы передать в hex.EncodeToString
	return hex.EncodeToString(h[:])
}

// hashSha512 вычисляет хеш SHA-512 от строки и возвращает его в виде hex-строки.
// Аналог crypto.createHash('sha512').digest('hex') в Node.js.
func hashSha512(text string) string {
	h := sha512.Sum512([]byte(text))
	return hex.EncodeToString(h[:])
}

// hmacSha256 вычисляет HMAC-SHA256 от текста с заданным ключом.
// Оба параметра — строки (в UTF-8).
// Аналог crypto.createHmac('sha256', key).digest('hex') в Node.js.
func hmacSha256(text, key string) string {
	// Создаём новый HMAC-хешер с алгоритмом SHA-256 и ключом
	h := hmac.New(sha256.New, []byte(key))
	// Добавляем данные для хеширования
	h.Write([]byte(text))
	// Получаем итоговый хеш как hex-строку
	return hex.EncodeToString(h.Sum(nil))
}

// hashConfig — карта соответствия типа данных и функции хеширования.
// Каждая функция принимает:
//   - text: строка для хеширования
//   - key: 32-байтный ключ в виде []byte (но внутри преобразуется в hex-строку)
//
// Выбор конкретной комбинации (combinedHash1..4) сделан для:
//   - предотвращения коллизий
//   - усложнения обратного подбора
//   - изоляции разных типов данных (даже при утечке одного хеша — другие остаются защищены)
var hashConfig = map[string]func(string, []byte) string{
	"USER_NAME":           combinedHash1,
	"USER_TG":             combinedHash2,
	"USER_PHONE":          combinedHash3,
	"USER_EMAIL":          combinedHash2,
	"INCIDENT_NAME":       combinedHash1,
	"VERIFY_TOKEN_STRING": combinedHash3,
	"INCIDENT_PHONE":      combinedHash2,
	"INCIDENT_TG":         combinedHash3,
	"API_KEY":             combinedHash4,
	"IDENTITY_KEY":        combinedHash2,
	"PASS_RESET_TOKEN":    combinedHash2,
	"BACKUP_EMAIL":        combinedHash2,
}

// combinedHash1 — комбинированный хеш: SHA256(SHA512(HMAC(text, key)) + HMAC(text, key))
// Уровень защиты: высокий (многослойный, использует два алгоритма хеширования)
func combinedHash1(text string, key []byte) string {
	// Преобразуем байтовый ключ в hex-строку, чтобы передать в HMAC
	// Это важно для совместимости с Node.js, где ключи часто хранятся/передаются как строки
	keyStr := hex.EncodeToString(key)
	// Вычисляем HMAC от текста
	hmacVal := hmacSha256(text, keyStr)
	// Комбинируем: SHA512(HMAC) + HMAC
	inner := hashSha512(hmacVal) + hmacVal
	// Финальный хеш — SHA256 от комбинации
	return hashSha256(inner)
}

// combinedHash2 — комбинированный хеш: SHA512(SHA256(HMAC(text, key)) + HMAC(text, key))
func combinedHash2(text string, key []byte) string {
	keyStr := hex.EncodeToString(key)
	hmacVal := hmacSha256(text, keyStr)
	inner := hashSha256(hmacVal) + hmacVal
	return hashSha512(inner)
}

// combinedHash3 — комбинированный хеш: HMAC(SHA512(text) + SHA256(text), key)
// Здесь HMAC применяется к комбинации "голых" хешей текста
func combinedHash3(text string, key []byte) string {
	keyStr := hex.EncodeToString(key)
	// Сначала хешируем текст двумя алгоритмами
	combinedText := hashSha512(text) + hashSha256(text)
	// Затем применяем HMAC с ключом
	return hmacSha256(combinedText, keyStr)
}

// combinedHash4 — самый сложный: HMAC(SHA512(SHA256(text) + SHA512(text) + SHA256(text)), key)
// Используется для самых чувствительных данных (например, API-ключей)
func combinedHash4(text string, key []byte) string {
	keyStr := hex.EncodeToString(key)
	// Многослойная комбинация хешей текста
	innerHash := hashSha512(hashSha256(text) + hashSha512(text) + hashSha256(text))
	// Финальный HMAC
	return hmacSha256(innerHash, keyStr)
}

// HashData применяет сконфигурированную функцию хеширования к тексту.
//
// Параметры:
//   - text: строка для хеширования (например, email, имя)
//   - dataType: тип данных, определяющий, какую функцию и ключ использовать
//
// Возвращает:
//   - hex-строку результата хеширования
//   - ошибку, если тип данных неизвестен или отсутствует ключ
//
// Особенности:
//   - Хеширование детерминировано: одинаковые вход → одинаковые выход
//   - Невозможно восстановить исходный текст из хеша (односторонняя функция)
//   - Каждый тип данных использует свой ключ → утечка одного хеша не компрометирует другие
func (cs *CryptoService) HashData(text string, dataType string) (string, error) {
	// Шаг 1: Находим функцию хеширования по типу данных
	fn, ok := hashConfig[dataType]
	if !ok {
		return "", fmt.Errorf("%w: %s", ErrUnknownDataType, dataType)
	}

	// Шаг 2: Получаем ключ для этого типа данных
	key, ok := cs.keys[dataType]
	if !ok {
		return "", fmt.Errorf("missing key for data type: %s", dataType)
	}

	// Шаг 3: Выполняем хеширование
	return fn(text, key), nil
}
