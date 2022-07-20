package utils

import (
	"bytes"
	"crypto/rand"
	"io"
)

// RandomBytes generate random bytes with specify size(bytes)
func RandomBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// PKCS7Padding pad block using pkcs7
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS7UnPadding unpad block using pkcs7
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
