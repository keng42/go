// Package random provides functions related to random strings.
package random

import (
	"crypto/rand"
	"encoding/ascii85"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
)

// NewBytes generates random bytes.
func NewBytes(len int) []byte {
	b := make([]byte, len)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

// NewTexts generates random texts and prints them out in specific numbers of characters.
func NewTexts() {
	b := NewBytes(128)
	s := hex.EncodeToString(b)
	fmt.Println("hex")
	print(s)

	b = NewBytes(128)
	s = base64.StdEncoding.EncodeToString(b)
	s = strings.ReplaceAll(s, "+", "")
	s = strings.ReplaceAll(s, "/", "")
	s = strings.ReplaceAll(s, "=", "")
	fmt.Println("base64")
	print(s)

	b = NewBytes(128)
	b2 := make([]byte, len(b)*2)
	ascii85.Encode(b2, b)
	s = string(b2)
	fmt.Println("ascii")
	print(s)
}

func print(s string) {
	if len(s) < 112 {
		return
	}
	fmt.Println("16", s[0:16])
	fmt.Println("32", s[16:48])
	fmt.Println("64", s[48:112])
	fmt.Println()
}
