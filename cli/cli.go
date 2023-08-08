package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"pwm/database"
	"strings"
	"sync"

	"golang.org/x/term"
)
var wg sync.WaitGroup

func Init() {
	fmt.Println("Do you wish to load passwords from a file? (Y, N)")

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	text := scanner.Text()

	switch strings.ToLower(text) {
		case "y":
			fmt.Println("Loading file with name:")
			scanner.Scan()
			name := scanner.Text()

			fmt.Println("Enter the password to this file")
			password, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				panic(err)
			}

			channel := make(chan *database.Database)
			go func() {
				db, err := database.FromFile(string(password), name)
				if err != nil {
					fmt.Println("Could not open file")
					panic(err)
				}
				channel <- db
				close(channel)
			}()

			cliLoop(scanner, channel)
		case "n":
			password := passwordConfirmation("Creating new database, what should the master password be?")

			channel := make(chan *database.Database)
			go func() {
				db, err := database.New(password)
				if err != nil {
					fmt.Println("Failed to create database")
					panic(err)
				}
				channel <- db
				close(channel)
			}()

			cliLoop(scanner, channel)
		default:
			fmt.Println("Unknown command")
			Init()
	}
}


func cliLoop(scanner *bufio.Scanner, channelDb chan *database.Database) {

	dbOpened := false

	for {
		fmt.Println("Welcome, to pwm: (help) for commands")
		scanner.Scan()
		command := scanner.Text()

		var db *database.Database //:= <- channelDb

		openDb := func() {
			if dbOpened == false {
				db = <- channelDb
			}
		}

		switch strings.ToLower(command) {
		case "q":
			fmt.Println("Exiting program.")
			openDb()
			return
		case "help":
			fmt.Println("q: exits program")
			fmt.Println("ls: lists accounts")
			fmt.Println("add: adds an account")
			fmt.Println("rm: removes an account")
			fmt.Println("get: gets a password")
			fmt.Println("save: encrypts the db and saves it to a file")
		case "ls":
			openDb()
			listAccounts(db)
		case "add":
			openDb()
			addAccount(db)
		case "rm":
			openDb()
			removeAccount(db)
		case "get":
			openDb()
			getPassword(db)
		case "save":
			openDb()
			channelDb = saveDatabase(db)
			dbOpened = false
		default:
			fmt.Println("Unknown command.")
		}
	}
}

func passwordConfirmation(message string) string {
	fmt.Println(message)

	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}

	fmt.Println("Enter password again to confirm")
	password2, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}

	if bytes.Compare(password, password2) != 0 {
		fmt.Println("Error passwords don't match")
		return passwordConfirmation(message)
	}

	return string(password)
}

func listAccounts(db *database.Database) {
	accounts := db.GetAccounts()
	for _, account := range accounts {
		fmt.Println(account)
	}
}

func addAccount(db *database.Database) {
	fmt.Println("Enter username")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	username := scanner.Text()

	password := passwordConfirmation("Enter user password")

	fmt.Println("Enter master password to confirm new account")
	masterPassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}

	err = db.AddAccount(string(masterPassword), username, string(password))
	if err != nil {
		fmt.Println("Failed to add account")
	}
}

func removeAccount(db *database.Database) {
	fmt.Println("Enter username")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	username := scanner.Text()

	fmt.Println("Enter master password to delete account")
	masterPassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}

	err = db.RemoveAccount(string(masterPassword), username)
	if err != nil {
		fmt.Println("Failed to remove account")
	}
}

func getPassword(db *database.Database) {
	fmt.Println("Enter username")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	username := scanner.Text()

	fmt.Println("Enter master password to retrieve password")
	masterPassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}

	password, err := db.GetPassword(string(masterPassword), username)
	if err != nil {
		fmt.Println("Failed to get account password")
	}
	fmt.Printf("Password: [%s]\n", password)
}

func saveDatabase(db *database.Database) chan *database.Database {
	fmt.Println("Enter name of file to save to")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	filename := scanner.Text()

	fmt.Println("Enter master password to save database")
	masterPassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		panic(err)
	}

	channelDb := make(chan *database.Database)
	go func(db *database.Database, masterPassword []byte, filename string) {
		err = db.ToFile(string(masterPassword), filename)
		if err != nil {
			fmt.Printf("Failed to save database to the file [%s]\n", filename)
		}

		channelDb <- db
		close(channelDb)
	}(db, masterPassword, filename)

	return channelDb
}


