package database

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
	"os"

	"pwm/encrypt"
	"pwm/serialize"
)

const (
	majorCost = 18
	minorCost = 12
)

type Database struct {
	data         map[string][]byte
	passwordHash []byte
}

func New(masterPassword string) (*Database, error) {
	var db Database
	var err error
	db.passwordHash, err = bcrypt.GenerateFromPassword([]byte(masterPassword), minorCost)
	if err != nil {
		return nil, err
	}

	db.data = make(map[string][]byte)

	return &db, nil
}

func Decrypt(masterPassword string, cipherBuffer []byte) (*Database, error) {
	buffer, err := encrypt.DecryptScrypt([]byte(masterPassword), cipherBuffer, majorCost)
	if err != nil {
		return nil, err
	}

	var db Database
	db.passwordHash, err = bcrypt.GenerateFromPassword([]byte(masterPassword), minorCost)
	if err != nil {
		return nil, err
	}

	db.data, err = serialize.DeserializeMap(buffer)
	if err != nil {
		return nil, err
	}

	return &db, nil
}

func (db *Database) Encrypt(masterPassword string) ([]byte, error) {
	err := bcrypt.CompareHashAndPassword(db.passwordHash, []byte(masterPassword))
	if err != nil {
		return nil, err
	}

	data, err := serialize.SerializeMap(&db.data)
	if err != nil {
		return nil, err
	}

	cipherBuffer, err := encrypt.EncryptScrypt([]byte(masterPassword), data, majorCost)

	return cipherBuffer, nil
}

func FromFile(masterPassword string, fileName string) (*Database, error) {
	content, err := os.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	return Decrypt(masterPassword, content)
}

func (db *Database) ToFile(masterPassword string, fileName string) error {
	contents, err := db.Encrypt(masterPassword)
	if err != nil {
		return err
	}

	return os.WriteFile(fileName, contents, 0644)
}

func (db *Database) AddAccount(masterPassword string, username string, password string) error {
	if _, ok := db.data[username]; ok {
		return errors.New("cannot overwrite passwords")
	}

	err := bcrypt.CompareHashAndPassword(db.passwordHash, []byte(masterPassword))
	if err != nil {
		return err
	}

	cipherText, err := encrypt.EncryptArgon2([]byte(masterPassword), []byte(password), 14)
	if err != nil {
		return err
	}

	db.data[username] = cipherText

	return nil
}

func (db *Database) RemoveAccount(masterPassword string, username string) error {
	if _, ok := db.data[username]; !ok {
		return errors.New("username not found")
	}

	err := bcrypt.CompareHashAndPassword(db.passwordHash, []byte(masterPassword))
	if err != nil {
		return err
	}

	delete(db.data, username)

	return nil
}

func (db *Database) GetPassword(masterPassword string, username string) (string, error) {
	if _, ok := db.data[username]; !ok {
		return string(""), errors.New("username not found")
	}

	err := bcrypt.CompareHashAndPassword(db.passwordHash, []byte(masterPassword))
	if err != nil {
		return "", err
	}

	plaintext, err := encrypt.DecryptArgon2([]byte(masterPassword), db.data[username], 14)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func (db *Database) GetAccounts() []string {
	keys := make([]string, 0, len(db.data))
	for k := range db.data {
		keys = append(keys, k)
	}
	return keys
}
