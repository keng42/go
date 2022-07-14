# go packages

[![Coverage Status](https://coveralls.io/repos/github/keng42/go/badge.svg)](https://coveralls.io/github/keng42/go)
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](https://github.com/keng42/go/blob/master/LICENSE)
[![API Reference](https://pkg.go.dev/badge/github.com/keng42/go)](https://pkg.go.dev/github.com/keng42/go)
[![Go Report Card](https://goreportcard.com/badge/github.com/keng42/go)](https://goreportcard.com/report/github.com/keng42/go)

## cnigma

The golang implementation of [cnigma](https://github.com/keng42/cnigma)

### Usage

```sh
go get github.com/keng42/go/cnigma
```

#### AES

```go
import (
	"fmt"
	"log"

	"github.com/keng42/go/cnigma/aes"
	"github.com/keng42/go/cnigma/aes/types"
)

func main() {
	aesgcm, err := NewAES(types.ModeGCM, types.DefaultKey, "my-password", types.Base64)
	if err != nil {
		log.Fatal(err)
	}

	ciphertext, err := aesgcm.EncryptText("hello world @ 2020", "")
	if err != nil {
		log.Fatal(err)
	}

	plaintext, err := aesgcm.DecryptText(ciphertext, "")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(plaintext)
	// Output: hello world @ 2020
}

```

#### RSA

```go
import (
	"fmt"
	"log"

	"github.com/keng42/go/cnigma/rsa"
	"github.com/keng42/go/cnigma/rsa/types"
)

func main() {
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
```
