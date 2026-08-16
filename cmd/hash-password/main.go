package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	password, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && len(password) == 0 {
		fmt.Fprintln(os.Stderr, "read password from stdin:", err)
		os.Exit(1)
	}
	password = strings.TrimRight(password, "\r\n")
	if len(password) < 12 || len(password) > 128 {
		fmt.Fprintln(os.Stderr, "password must contain 12-128 characters")
		os.Exit(1)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hash password:", err)
		os.Exit(1)
	}
	fmt.Println(string(hash))
}
