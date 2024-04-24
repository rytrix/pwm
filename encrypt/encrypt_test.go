package encrypt_test

import (
	"errors"
	"strings"
	"testing"

	"pwm/encrypt"
	"pwm/salt"
)

func TestArgon2_1(t *testing.T) {
	plaintext := " asdkadkal028032;kdHI HELLO!2345"
	password := "password123"

	saltResult, err := salt.Argon2([]byte(password), nil, 14)
	if err != nil {
		t.Error(err)
	}
	ciphertext, err := encrypt.Encrypt(saltResult, []byte(plaintext))
	if err != nil {
		t.Error(err)
	}

	password = "password123"
	saltResult, err = salt.Argon2([]byte(password), ciphertext[:salt.SaltLength], 14)
	if err != nil {
		t.Error(err)
	}

	decryptedtext, err := encrypt.Decrypt(saltResult.Key, ciphertext)
	if err != nil {
		t.Error(err)
	}

	if strings.Compare(plaintext, string(decryptedtext)) != 0 {
		t.Error("original string and decrypted string are not the same")
	}
}

func TestArgon2_2(t *testing.T) {
	plaintext := "asdkadkal028032;kdHI HELLO!2345"
	password := "password123"

	ciphertext, err := encrypt.EncryptArgon2([]byte(password), []byte(plaintext), 14)
	if err != nil {
		t.Error(err)
	}

	password = "password123"
	decryptedtext, err := encrypt.DecryptArgon2([]byte(password), ciphertext, 14)
	if err != nil {
		t.Error(err)
	}

	if strings.Compare(plaintext, string(decryptedtext)) != 0 {
		t.Error("original string and decrypted string are not the same")
	}
}

func TestArgon2_3(t *testing.T) {
	password := "password123"

	saltResult, err := salt.Argon2([]byte(password), nil, 14)
	if err != nil {
		t.Error(err)
	}

	var zeros [16]byte

	if saltResult.Salt == zeros {
		t.Error(errors.New("saltResult gives a salt of zeros"))
	}
}

func TestScrypt_1(t *testing.T) {
	plaintext := " asdkadkal028032;kdHI HELLO!2345"
	password := "password123"

	saltResult, err := salt.Scrypt([]byte(password), nil, 14)
	if err != nil {
		t.Error(err)
	}
	ciphertext, err := encrypt.Encrypt(saltResult, []byte(plaintext))
	if err != nil {
		t.Error(err)
	}

	password = "password123"
	saltResult, err = salt.Scrypt([]byte(password), ciphertext[:salt.SaltLength], 14)
	if err != nil {
		t.Error(err)
	}

	decryptedtext, err := encrypt.Decrypt(saltResult.Key, ciphertext)
	if err != nil {
		t.Error(err)
	}

	if strings.Compare(plaintext, string(decryptedtext)) != 0 {
		t.Error("original string and decrypted string are not the same")
	}
}

func TestScrypt_2(t *testing.T) {
	plaintext := "asdkadkal028032;kdHI HELLO!2345"
	password := "password123"

	ciphertext, err := encrypt.EncryptScrypt([]byte(password), []byte(plaintext), 14)
	if err != nil {
		t.Error(err)
	}

	password = "password123"
	decryptedtext, err := encrypt.DecryptScrypt([]byte(password), ciphertext, 14)
	if err != nil {
		t.Error(err)
	}

	if strings.Compare(plaintext, string(decryptedtext)) != 0 {
		t.Error("original string and decrypted string are not the same")
	}
}

func TestScrypt_3(t *testing.T) {
	password := "password123"

	saltResult, err := salt.Scrypt([]byte(password), nil, 14)
	if err != nil {
		t.Error(err)
	}

	var zeros [16]byte

	if saltResult.Salt == zeros {
		t.Error(errors.New("saltResult gives a salt of zeros"))
	}
}
