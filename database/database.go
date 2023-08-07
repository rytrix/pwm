package database

import (
	"pwm/scrypt"
	"pwm/serialize"
	"golang.org/x/crypto/bcrypt"
	"errors"
)

type Database struct {
	data map[string][]byte
	passwordHash []byte
}

func New(masterPassword string) (*Database, error) {
	var db Database
	var err error
	db.passwordHash, err = bcrypt.GenerateFromPassword([]byte(masterPassword), 12)
	if err != nil {
		return nil, err
	}

	db.data = make(map[string][]byte)
	
	return &db, nil
}

func Decrypt(masterPassword string, cipherBuffer []byte) (*Database, error) {
	buffer, err := scrypt.Decrypt([]byte(masterPassword), cipherBuffer, 18)
	if err != nil {
		return nil, err
	}

	var db Database
	db.passwordHash, err = bcrypt.GenerateFromPassword([]byte(masterPassword), 12)
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

	cipherBuffer, err := scrypt.Encrypt([]byte(masterPassword), data, 18)

	return cipherBuffer, nil
}

func (db *Database) AddAccount(masterPassword string, username string, password string) error {
	if _, ok := db.data[username]; ok {
		return errors.New("cannot overwrite passwords")
	}

	err := bcrypt.CompareHashAndPassword(db.passwordHash, []byte(masterPassword))
	if err != nil {
		return err
	}

	cipherText, err := scrypt.Encrypt([]byte(masterPassword), []byte(password), 10)
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
		return string(""), err
	}

	plaintext, err := scrypt.Decrypt([]byte(masterPassword), db.data[username], 10)
	if err != nil {
		return string(""), err
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


