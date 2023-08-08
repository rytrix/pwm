package argon2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"golang.org/x/crypto/argon2"
)

const (
	argon2T = 15
	argon2M = 1 << 18
	argon2P = 4
	saltLength = 16
)

// Recommended cost as of 2023 is somewhere around 18
func Encrypt(password []byte, plaintext []byte, cost int) ([]byte, error) {
	var salt [saltLength]byte
	_, err := rand.Read(salt[:])
	if err != nil {
		return nil, err
	}
	
	argon2T := uint32(cost)
	argon2M := uint32(1 << cost)
	key := argon2.IDKey(password, salt[:], argon2T, argon2M, argon2P, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// putting the salt at the end of the nonce heap, this will be included at the start of the ciphertext
	// ========== // =========== // ============ //
	//   salt     //    nonce    //  ciphertext  //
	nonce := make([]byte, saltLength + gcm.NonceSize())
	copy(nonce[:saltLength], salt[:])

	_, err = rand.Read(nonce[saltLength:])
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce[saltLength:saltLength + gcm.NonceSize()], plaintext, nil)

	return ciphertext, nil
}

// Recommended cost as of 2023 is somewhere around 18
func Decrypt(password []byte, ciphertext []byte, cost int) ([]byte, error) {
	argon2T := uint32(cost)
	argon2M := uint32(1 << cost)
	key := argon2.IDKey(password, ciphertext[:saltLength], argon2T, argon2M, argon2P, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// putting the salt at the end of the nonce heap, this will be included at the start of the ciphertext
	// ========== // =========== // ============ //
	//   salt     //    nonce    //  ciphertext  //
	nonce := ciphertext[saltLength:saltLength + gcm.NonceSize()]
	decryptedtext, err := gcm.Open(nil, nonce, ciphertext[saltLength+gcm.NonceSize():], nil)
	if err != nil {
		return nil, err
	}

	return decryptedtext, nil
}
