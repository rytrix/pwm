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

func Create(masterPassword []byte, cipherBuffer []byte) (*Database, error) {
	buffer, err := scrypt.Decrypt(masterPassword, cipherBuffer, 18)
	if err != nil {
		return nil, err
	}

	var db Database
	db.passwordHash, err = bcrypt.GenerateFromPassword(masterPassword, 12)

	db.data, err = serialize.DeserializeMap(buffer)
	if err != nil {
		return nil, err
	}
	
	return &db, nil
}

func (db *Database) Encrypt(masterPassword []byte) ([]byte, error) {
	err := bcrypt.CompareHashAndPassword(db.passwordHash, masterPassword)
	if err != nil {
		return nil, err
	}

	data, err := serialize.SerializeMap(&db.data)
	if err != nil {
		return nil, err
	}

	cipherBuffer, err := scrypt.Encrypt(masterPassword, data, 18)

	return cipherBuffer, nil
}

func (db *Database) AddPassword(username string, password string) error {
	if _, ok := db.data[username]; ok {
		return errors.New("cannot overwrite passwords")
	}

	cipherText, err := scrypt.Encrypt(db.passwordHash, []byte(password), 10)
	if err != nil {
		return err
	}

	db.data[username] = cipherText

	return nil
}

func (db *Database) RemovePassword(username string, masterPassword string) error {
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

func (db *Database) GetUsernames() []string {
	keys := make([]string, 0, len(db.data))
	for k := range db.data {
		keys = append(keys, k)
	}
	return keys
}


