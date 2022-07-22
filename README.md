# go packages

[![Coverage Status](https://coveralls.io/repos/github/keng42/go/badge.svg)](https://coveralls.io/github/keng42/go)
[![MIT License](http://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](https://github.com/keng42/go/blob/master/LICENSE)
[![API Reference](https://pkg.go.dev/badge/github.com/keng42/go)](https://pkg.go.dev/github.com/keng42/go)
[![Go Report Card](https://goreportcard.com/badge/github.com/keng42/go)](https://goreportcard.com/report/github.com/keng42/go)

[cnigma](#cnigma)  
[random](#random)

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

## random

A simple app for generating random strings.

### Usage

```sh
go install github.com/keng42/go/cmd/random

random
```

Example output:

```
hex
16 e6490cd6bb281fde
32 4a569b71d9e49b00454bd6b6d72073e0
64 09f34cfe26a3d4589bfff3220c3025331f7987793f3d433e87f7351ddc4317f5

base64
16 MoXXjCtj0xauGwo6
32 cKoWekLvPCBnEItEkd16GujjycUyV7yE
64 zv6dZHby9uZQKXCr72IL75yDQc6MzSBkM4J9StPAeWQIUZTmDSApmVEWQxzXYbZu

ascii
16 M#7A!->jt48N>`!G
32 QJOl6XJZAdk^E&9''3+;CO?r*?YnYXe_
64 ,B(i<,O<.C@SJYEjK=c)h6(Mh#C>8RUJUKS2QbWa>l`Mm't>\opMmN<o,Ac4OAZA
```
