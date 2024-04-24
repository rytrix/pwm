package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"pwm/salt"
)

const KeyLength = 32

func EncryptArgon2(password []byte, plaintext []byte, cost int) ([]byte, error) {
	saltResult, err := salt.Argon2([]byte(password), nil, cost)
	if err != nil {
		return nil, err
	}
	ciphertext, err := Encrypt(saltResult, []byte(plaintext))
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func DecryptArgon2(password []byte, ciphertext []byte, cost int) ([]byte, error) {
	saltResult, err := salt.Argon2([]byte(password), ciphertext[:salt.SaltLength], cost)
	if err != nil {
		return nil, err
	}

	decryptedtext, err := Decrypt(saltResult.Key, ciphertext)
	if err != nil {
		return nil, err
	}

	return decryptedtext, nil
}

func EncryptScrypt(password []byte, plaintext []byte, cost int) ([]byte, error) {
	saltResult, err := salt.Scrypt([]byte(password), nil, cost)
	if err != nil {
		return nil, err
	}
	ciphertext, err := Encrypt(saltResult, []byte(plaintext))
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func DecryptScrypt(password []byte, ciphertext []byte, cost int) ([]byte, error) {
	saltResult, err := salt.Scrypt([]byte(password), ciphertext[:salt.SaltLength], cost)
	if err != nil {
		return nil, err
	}

	decryptedtext, err := Decrypt(saltResult.Key, ciphertext)
	if err != nil {
		return nil, err
	}

	return decryptedtext, nil
}

func Encrypt(saltResult salt.SaltResult, plaintext []byte) ([]byte, error) {
	if len(saltResult.Key) != KeyLength {
		return nil, errors.New("saltedKey needs to be 32 bytes")
	}

	block, err := aes.NewCipher(saltResult.Key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// putting the salt at the start of the nonce heap, this will be included at the start of the ciphertext
	// ========== // =========== // ============ //
	//   salt     //    nonce    //  ciphertext  //
	nonce := make([]byte, salt.SaltLength+gcm.NonceSize())
	copy(nonce[:salt.SaltLength], saltResult.Salt[:])

	_, err = rand.Read(nonce[salt.SaltLength:])
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce[salt.SaltLength:salt.SaltLength+gcm.NonceSize()], plaintext, nil)

	return ciphertext, nil
}

func Decrypt(saltedKey []byte, ciphertext []byte) ([]byte, error) {
	if len(saltedKey) != KeyLength {
		return nil, errors.New("saltedKey needs to be 32 bytes")
	}

	block, err := aes.NewCipher(saltedKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// putting the salt at the start of the nonce heap, this will be included at the start of the ciphertext
	// ========== // =========== // ============ //
	//   salt     //    nonce    //  ciphertext  //
	nonce := ciphertext[salt.SaltLength : salt.SaltLength+gcm.NonceSize()]
	if len(nonce) > len(ciphertext) {
		return nil, errors.New("Cannot decrypt file")
	}
	decryptedtext, err := gcm.Open(nil, nonce, ciphertext[salt.SaltLength+gcm.NonceSize():], nil)
	if err != nil {
		return nil, err
	}

	return decryptedtext, nil
}
