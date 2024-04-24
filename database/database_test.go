package database_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"pwm/database"
)

func searchArrayForName(array []string, name string) error {
	for _, str := range array {
		if strings.Compare(str, name) == 0 {
			return nil
		}
	}

	return errors.New(fmt.Sprintf("failed to find name %s", name))
}

func TestDatabase(t *testing.T) {
	db, err := database.New("password")
	if err != nil {
		t.Error(err)
	}

	if err := db.AddAccount("password", "user1", "thisiscorrect!"); err != nil {
		t.Error(err)
	}
	if err := db.AddAccount("password", "user2", "thisiscorrect2!"); err != nil {
		t.Error(err)
	}
	if err := db.AddAccount("password", "user3", "thisiscorrect3!"); err != nil {
		t.Error(err)
	}

	accounts := db.GetAccounts()
	err = searchArrayForName(accounts[:], "user1")
	if err != nil {
		t.Error(err)
	}
	err = searchArrayForName(accounts[:], "user2")
	if err != nil {
		t.Error(err)
	}
	err = searchArrayForName(accounts[:], "user3")
	if err != nil {
		t.Error(err)
	}

	pw, err := db.GetPassword("password", "user1")
	if err != nil {
		t.Error(err)
	}
	if strings.Compare(pw, "thisiscorrect!") != 0 {
		t.Error("user1 password incorrect")
	}

	pw, err = db.GetPassword("password", "user2")
	if err != nil {
		t.Error(err)
	}
	if strings.Compare(pw, "thisiscorrect2!") != 0 {
		t.Error("user2 password incorrect")
	}

	pw, err = db.GetPassword("password", "user3")
	if err != nil {
		t.Error(err)
	}
	if strings.Compare(pw, "thisiscorrect3!") != 0 {
		t.Error("user3 password incorrect")
	}

	ciphertext, err := db.Encrypt("password")
	if err != nil {
		t.Error(err)
	}

	db, err = database.Decrypt("password", ciphertext)
	if err != nil {
		t.Error(err)
	}

	pw, err = db.GetPassword("password", "user1")
	if err != nil {
		t.Error(err)
	}
	if strings.Compare(pw, "thisiscorrect!") != 0 {
		t.Error("user1 password incorrect")
	}

	pw, err = db.GetPassword("password", "user2")
	if err != nil {
		t.Error(err)
	}
	if strings.Compare(pw, "thisiscorrect2!") != 0 {
		t.Error("user2 password incorrect")
	}

	pw, err = db.GetPassword("password", "user3")
	if err != nil {
		t.Error(err)
	}
	if strings.Compare(pw, "thisiscorrect3!") != 0 {
		t.Error("user3 password incorrect")
	}

	// test remove
	err = db.RemoveAccount("password", "user1")
	if err != nil {
		t.Error(err)
	}

	pw, err = db.GetPassword("password", "user1")
	if err == nil {
		t.Error("expected to be unable to find account")
	}
}
