package salt

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

const (
	argon2T = 15
	argon2M = 1 << 18
	argon2P = 4

	scryptN = 2 << 17 // cost of 2^18
	scryptR = 8
	scryptP = 4

	SaltLength = 16
)

type SaltResult struct {
	Key  []byte
	Salt [SaltLength]byte
}

// recommended cost as of 2023 is 18
// salt can be nil if a random number is to be generated
func Argon2(password []byte, salt []byte, cost int) (SaltResult, error) {
	result := SaltResult{}
	var err error

	if salt == nil {
		_, err = rand.Read(result.Salt[:])
		if err != nil {
			return result, err
		}
	} else {
		if len(salt) != SaltLength {
			return result, errors.New(fmt.Sprintf("salt is expected to be %d bytes long", SaltLength))
		}
		copy(result.Salt[:], salt)
	}

	argon2T := uint32(cost)
	argon2M := uint32(1 << cost)
	result.Key = argon2.IDKey(password, result.Salt[:], argon2T, argon2M, argon2P, 32)

	return result, nil
}

// recommended cost as of 2023 is 18
// salt can be nil if a random number is to be generated
func Scrypt(password []byte, salt []byte, cost int) (SaltResult, error) {
	result := SaltResult{}
	var err error

	if salt == nil {
		_, err = rand.Read(result.Salt[:])
		if err != nil {
			return result, err
		}
	} else {
		if len(salt) != SaltLength {
			return result, errors.New(fmt.Sprintf("salt is expected to be %d bytes long", SaltLength))
		}
		copy(result.Salt[:], salt)
	}

	scryptN := 2 << (cost - 1) // 2 ^ cost
	result.Key, err = scrypt.Key(password, result.Salt[:], scryptN, scryptR, scryptP, 32)
	if err != nil {
		return result, err
	}

	return result, nil
}
