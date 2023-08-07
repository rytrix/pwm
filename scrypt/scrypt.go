package scrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"golang.org/x/crypto/scrypt"
)

const (
	scryptN = 2 << 17 // cost of 2^18
	scryptR = 8
	scryptP = 1
	saltLength = 16
)

// Recommended cost as of 2023 is somewhere around 18
func Encrypt(password []byte, plaintext []byte, cost int) ([]byte, error) {
	var salt [saltLength]byte
	_, err := rand.Read(salt[:])
	if err != nil {
		return nil, err
	}
	
	scryptN := 2 << (cost - 1) // 2 ^ cost
	key, err := scrypt.Key(password, salt[:], scryptN, scryptR, scryptP, 32)
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
	scryptN := 2 << (cost - 1) // 2 ^ cost
	key, err := scrypt.Key(password, ciphertext[:saltLength], scryptN, scryptR, scryptP, 32)
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
	nonce := ciphertext[saltLength:saltLength + gcm.NonceSize()]
	decryptedtext, err := gcm.Open(nil, nonce, ciphertext[saltLength+gcm.NonceSize():], nil)
	if err != nil {
		return nil, err
	}

	return decryptedtext, nil
}

