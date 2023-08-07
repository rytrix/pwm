package main

import (
	"fmt"
	// "pwm/argon2"
	"pwm/scrypt"
	// "pwm/serialize"
	// "golang.org/x/crypto/bcrypt"
)

func main() {
	plaintext := "hello world 123143242342342342353434535343as;daldaa HI HELLO!2345"
	password := "idkasdada93223hdjahdadahdakjhda87dyadiahjdakjdahkdjashdkjahsdjkahdjhadjha"

	ciphertext, err := scrypt.Encrypt([]byte(password), []byte(plaintext), 18)
	if err != nil {
		panic(err)
	}
	fmt.Println("ciphertext", ciphertext)

	password = "idkasdada93223hdjahdadahdakjhda87dyadiahjdakjdahkdjashdkjahsdjkahdjhadjha"
	decryptedtext, err := scrypt.Decrypt([]byte(password), ciphertext, 18)
	if err != nil {
		panic(err)
	}
	fmt.Println("decryptedtext", string(decryptedtext))

}




