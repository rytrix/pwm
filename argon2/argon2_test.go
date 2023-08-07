package argon2_test

import (
	"pwm/argon2"
	"strings"
	"testing"
)

func TestScrypt(t *testing.T) {
	plaintext := "hello world 123143242342342342353434535343as;daldaa HI HELLO!2345"
	password := "idkasdada93223hdjahdadahdakjhda87dyadiahjdakjdahkdjashdkjahsdjkahdjhadjha"

	ciphertext, err := argon2.Encrypt([]byte(password), []byte(plaintext), 14)
	if err != nil {
		t.Error(err)
	}

	password = "idkasdada93223hdjahdadahdakjhda87dyadiahjdakjdahkdjashdkjahsdjkahdjhadjha"
	decryptedtext, err := argon2.Decrypt([]byte(password), ciphertext, 14)
	if err != nil {
		t.Error(err)
	}

	if strings.Compare(plaintext, string(decryptedtext)) != 0 {
		t.Error("original string and decrypted string are not the same")
	}
}

