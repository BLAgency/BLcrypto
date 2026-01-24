package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// DecryptFrontCBC расшифровывает данные, зашифрованные на фронтенде с использованием AES-CBC.
// Ожидается, что данные были зашифрованы с тем же 32-байтным ключом, что и хранится в cs.keys[dataType].
//
// Параметры:
//   - encryptedHex: зашифрованные данные в виде шестнадцатеричной строки (hex)
//   - ivHex: вектор инициализации (IV) в виде шестнадцатеричной строки (должен быть 16 байт)
//   - dataType: тип данных, определяющий, какой ключ использовать (например, "FRONT_KEY_1")
//
// Возвращает:
//   - map[string]interface{}: распарсированный JSON-объект из расшифрованных данных
//   - error: ошибка, если расшифровка или парсинг не удалась
//
// Особенности реализации:
//   - Используется режим шифрования AES-256-CBC (ключ 32 байта → AES-256)
//   - Padding предполагается PKCS#7 (стандарт для AES в большинстве библиотек, включая Node.js)
//   - Все входные данные передаются как hex-строки (как в оригинальном JS-коде)
func (cs *CryptoService) DecryptFrontCBC(encryptedHex, ivHex, dataType string) (map[string]interface{}, error) {
	// Шаг 1: Получаем криптографический ключ по имени типа данных (например, "FRONT_KEY_1")
	key, ok := cs.keys[dataType]
	if !ok {
		// Если ключ не найден — возвращаем понятную ошибку
		return nil, fmt.Errorf("%w: %s", ErrUnknownDataType, dataType)
	}

	// Шаг 2: Декодируем hex-строку зашифрованных данных в байты
	encrypted, err := hex.DecodeString(encryptedHex)
	if err != nil {
		// Некорректный hex → ошибка
		return nil, err
	}

	// Шаг 3: Декодируем hex-строку IV (вектора инициализации) в байты
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return nil, err
	}

	// Шаг 4: Проверяем, что длина IV равна размеру блока AES (16 байт)
	// Это критически важно: CBC требует IV = block size
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV must be %d bytes for AES-CBC", aes.BlockSize)
	}

	// Шаг 5: Проверяем, что длина зашифрованных данных кратна размеру блока
	// Иначе это не валидный CBC-шифротекст
	if len(encrypted)%aes.BlockSize != 0 {
		return nil, ErrDecryption
	}

	// Шаг 6: Создаём AES-шифр на основе 32-байтного ключа (AES-256)
	block, err := aes.NewCipher(key)
	if err != nil {
		// Теоретически не должно происходить при 32-байтном ключе, но проверяем
		return nil, err
	}

	// Шаг 7: Создаём дешифратор в режиме CBC с заданным IV
	mode := cipher.NewCBCDecrypter(block, iv)

	// Шаг 8: Расшифровываем данные "на месте" (in-place decryption)
	// Входной и выходной буфер — один и тот же (encrypted)
	mode.CryptBlocks(encrypted, encrypted)

	// Шаг 9: Удаляем PKCS#7 padding вручную
	// Последний байт расшифрованного текста указывает, сколько байт padding'а
	padding := encrypted[len(encrypted)-1]

	// Валидация padding:
	// - padding не может быть 0 (минимум 1 байт)
	// - padding не может превышать длину всего сообщения
	if padding == 0 || int(padding) > len(encrypted) {
		return nil, ErrDecryption
	}

	// Проверяем, что все padding-байты имеют одно и то же значение (как того требует PKCS#7)
	for i := 0; i < int(padding); i++ {
		if encrypted[len(encrypted)-1-i] != padding {
			return nil, ErrDecryption
		}
	}

	// Удаляем padding: обрезаем последние N байт
	plaintext := encrypted[:len(encrypted)-int(padding)]

	// Шаг 10: Парсим полученный текст как JSON
	var result map[string]interface{}
	if err := json.Unmarshal(plaintext, &result); err != nil {
		// Если JSON невалиден — ошибка
		return nil, err
	}

	// Шаг 11: Возвращаем распарсированный объект
	return result, nil
}
