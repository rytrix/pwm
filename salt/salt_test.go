package salt_test

import (
	"errors"
	"pwm/encrypt"
	"pwm/salt"
	"strings"
	"testing"
)

func TestArgon2(t *testing.T) {
	plaintext := "hello world 123143242342342342353434535343as;daldaa HI HELLO!2345"
	password := "idkasdada93223hdjahdadahdakjhda87dyadiahjdakjdahkdjashdkjahsdjkahdjhadjha"

	saltResult, err := salt.Argon2([]byte(password), nil, 14)
	if err != nil {
		t.Error(err)
	}
	var zeros [16]byte
	if saltResult.Salt == zeros {
		t.Error(errors.New("saltResult contains a salt of zeros"))
	}

	ciphertext, err := encrypt.Encrypt(saltResult, []byte(plaintext))
	if err != nil {
		t.Error(err)
	}

	password = "idkasdada93223hdjahdadahdakjhda87dyadiahjdakjdahkdjashdkjahsdjkahdjhadjha"
	saltResult, err = salt.Argon2([]byte(password), ciphertext[:salt.SaltLength], 14)
	if err != nil {
		t.Error(err)
	}
	if saltResult.Salt == zeros {
		t.Error(errors.New("saltResult contains a salt of zeros"))
	}

	decryptedtext, err := encrypt.Decrypt(saltResult.Key, ciphertext)
	if err != nil {
		t.Error(err)
	}

	if strings.Compare(plaintext, string(decryptedtext)) != 0 {
		t.Error("original string and decrypted string are not the same")
	}
}

func TestScrypt(t *testing.T) {
	plaintext := "hello world 123143242342342342353434535343as;daldaa HI HELLO!2345"
	password := "idkasdada93223hdjahdadahdakjhda87dyadiahjdakjdahkdjashdkjahsdjkahdjhadjha"

	saltResult, err := salt.Scrypt([]byte(password), nil, 14)
	if err != nil {
		t.Error(err)
	}

	var zeros [16]byte
	if saltResult.Salt == zeros {
		t.Error(errors.New("saltResult contains a salt of zeros"))
	}

	ciphertext, err := encrypt.Encrypt(saltResult, []byte(plaintext))
	if err != nil {
		t.Error(err)
	}

	password = "idkasdada93223hdjahdadahdakjhda87dyadiahjdakjdahkdjashdkjahsdjkahdjhadjha"
	saltResult, err = salt.Scrypt([]byte(password), ciphertext[:salt.SaltLength], 14)
	if err != nil {
		t.Error(err)
	}
	if saltResult.Salt == zeros {
		t.Error(errors.New("saltResult contains a salt of zeros"))
	}

	decryptedtext, err := encrypt.Decrypt(saltResult.Key, ciphertext)
	if err != nil {
		t.Error(err)
	}

	if strings.Compare(plaintext, string(decryptedtext)) != 0 {
		t.Error("original string and decrypted string are not the same")
	}
}
