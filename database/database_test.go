package database_test

import (
	"pwm/database"
	"strings"
	"testing"
)

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
	if strings.Compare(accounts[0], "user1") != 0 {
		t.Error("user1 is incorrect")
	}
	if strings.Compare(accounts[1], "user2") != 0 {
		t.Error("user2 is incorrect")
	}
	if strings.Compare(accounts[2], "user3") != 0 {
		t.Error("user3 is incorrect")
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

