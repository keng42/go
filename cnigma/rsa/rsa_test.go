package rsa_test

import (
	"fmt"
	"log"
	"testing"

	"github.com/keng42/go/cnigma/rsa"
	"github.com/keng42/go/cnigma/rsa/types"
	"github.com/stretchr/testify/require"
)

func TestLoadPrivateKey(t *testing.T) {
	priv, err := rsa.LoadPrivateKey("../testdata/rsa-private-pkcs8.key")
	require.Nil(t, err)
	require.NotNil(t, priv)
}

func TestNewRSA(t *testing.T) {
	priv, err := rsa.LoadPrivateKey("../testdata/rsa-private-pkcs8.key")
	require.Nil(t, err)

	r, _ := rsa.NewRSA(types.Hex)
	r.PrivateKey = priv
	r.PublicKey = &priv.PublicKey

	msg := "hello world @ 2020"

	// Sign message with private key
	sig, err := r.Sign(msg)
	require.Nil(t, err)
	require.Len(t, sig, 1024)

	// Verify message with public key
	verified, err := r.Verify(msg, sig)
	require.Nil(t, err)
	require.True(t, verified)

	verified, err = r.Verify(msg+"?", sig)
	require.Nil(t, err)
	require.False(t, verified)

	// Encrypt text with public key
	ciphertext, err := r.Encrypt(msg)
	require.Nil(t, err)
	require.Len(t, ciphertext, 1024)

	// Decrypt text with private key
	plaintext, err := r.Decrypt(ciphertext)
	require.Nil(t, err)
	require.Equal(t, msg, plaintext)
}

func ExampleNewRSA() {
	priv, err := rsa.LoadPrivateKey("../testdata/rsa-private-pkcs8.key")
	if err != nil {
		log.Fatal(err)
	}

	r, _ := rsa.NewRSA(types.Hex)
	r.PrivateKey = priv
	r.PublicKey = &priv.PublicKey

	msg := "hello world @ 2020"

	// Sign message with private key
	sig, err := r.Sign(msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("sig", sig)

	// Verify message with public key
	verified, err := r.Verify(msg, sig)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("verified", verified)

	// Encrypt text with public key
	ciphertext, err := r.Encrypt(msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("ciphertext", ciphertext)

	// Decrypt text with private key
	plaintext, err := r.Decrypt(ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("plaintext", plaintext)
}
