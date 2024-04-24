package main

import (
	"fmt"
	"pwm/cli"
)

func main() {
	err := cli.Init()
	if err != nil {
		fmt.Println("Action failed")
	}
}
