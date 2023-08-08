package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"pwm/database"
	"pwm/scrypt"
	"strings"
	"golang.org/x/term"
)

func Init() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: --encrypt <file> --decrypt <file> --file <file> --new")
	} else {
		switch strings.ToLower(os.Args[1]) {
			case "--encrypt":
				if len(os.Args) < 3 {
					fmt.Println("Expected file\nUsage: --encrypt <file>")
				} else {
					contents, err := os.ReadFile(os.Args[2])
					if err != nil {
						panic(err)
					}
					password := passwordConfirmation("What will the password be for this file?")

					fmt.Println("Encrypting", os.Args[2])
					ciphertext, err := scrypt.Encrypt([]byte(password), contents, 18)
					if err != nil {
						panic(err)
					}

					var outfile string
					if len(os.Args) >= 5 && strings.Compare(os.Args[3], "-o") == 0 {
						outfile = os.Args[4]
					} else {
						outfile = os.Args[2]
					}
					
					fmt.Printf("Writing to %s\n", outfile)
					err = os.WriteFile(outfile, ciphertext, 0644)
					if err != nil {
						panic(err)
					}
				}
			case "--decrypt":
				if len(os.Args) < 3 {
					fmt.Println("Expected file\nUsage: --decrypt <file>")
				} else {
					contents, err := os.ReadFile(os.Args[2])
					if err != nil {
						panic(err)
					}
					fmt.Println("Enter the files password")
					password, err := term.ReadPassword(int(os.Stdin.Fd()))
					if err != nil {
						panic(err)
					}

					fmt.Println("Decrypting", os.Args[2])
					ciphertext, err := scrypt.Decrypt([]byte(password), contents, 18)
					if err != nil {
						panic(err)
					}

					var outfile string
					if len(os.Args) >= 5 && strings.Compare(os.Args[3], "-o") == 0 {
						outfile = os.Args[4]
					} else {
						outfile = os.Args[2]
					}
					
					fmt.Printf("Writing to %s\n", outfile)
					err = os.WriteFile(outfile, ciphertext, 0644)
					if err != nil {
						panic(err)
					}
				}
			case "--file":
				if len(os.Args) < 3 {
					fmt.Println("Expected file\nUsage: --file <file>")
				} else {
					fmt.Println("Enter the password to this file")
					password, err := term.ReadPassword(int(os.Stdin.Fd()))
					if err != nil {
						panic(err)
					}

					channel := make(chan *database.Database)
					go func() {
						db, err := database.FromFile(string(password), os.Args[2])
						if err != nil {
							fmt.Println("Could not open file")
							panic(err)
						}
						channel <- db
						close(channel)
					}()

					cliLoop(channel)
				}
			case "--new":
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

				cliLoop(channel)
			default:
				fmt.Println("Usage: --encrypt <file> --decrypt <file> --file <file> --new")
		}
	}
}

func cliLoop(channelDb chan *database.Database) {

	scanner := bufio.NewScanner(os.Stdin)
	dbOpened := false
	var db *database.Database = nil	

	for {
		fmt.Println("Welcome, to pwm: (help) for commands")
		scanner.Scan()
		command := scanner.Text()

		openDb := func() {
			if dbOpened == false {
				db = <- channelDb
				dbOpened = true
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


