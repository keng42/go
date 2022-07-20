package aes_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/keng42/go/cnigma/aes"
	"github.com/keng42/go/cnigma/aes/types"
	"github.com/stretchr/testify/require"
)

func ExampleNewAES() {
	aesgcm, err := aes.NewAES(types.ModeGCM, types.DefaultKey, "my-password", types.Base64)
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

func ExampleAES_EncryptFile() {
	aescbc, err := aes.NewAES(types.ModeCBC, "", "", types.Base64)
	if err != nil {
		log.Fatal(err)
	}

	err = aescbc.EncryptFile("../testdata/xxy007.png", "../testdata/xxy007.png.cbc", "")
	if err != nil {
		log.Fatal(err)
	}

	err = aescbc.DecryptFile("../testdata/xxy007.png.cbc", "../testdata/xxy007.cbc.png", "")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(fileHash("../testdata/xxy007.cbc.png"))
	// Output: a818b30f2ddbb4bd5d77acaa33bb037ba0b92add5159c8b49c9923295bdaf59a
}

func fileHash(filepath string) string {
	f, err := os.Open(filepath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	return hex.EncodeToString(h.Sum(nil))
}

func TestGCMText(t *testing.T) {
	aesgcm, err := aes.NewAES("gcm", "", "my-password", types.Base64)
	require.Nil(t, err)

	plaintext := "hello world @ 2020"
	ciphertext, err := aesgcm.EncryptText(plaintext, "")
	require.Nil(t, err)

	decrypted, err := aesgcm.DecryptText(ciphertext, "")
	require.Nil(t, err)
	require.Equal(t, plaintext, decrypted)

	// ciphertext from cnigma-ts
	decrypted, err = aesgcm.DecryptText("AQLV3eYPTOMhNec2Q69aY0Y3dOhbSTW4HMgmFucRugX5y9eY2nvXeMl/Zy8PVOpV", "")
	require.Nil(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestCBCText(t *testing.T) {
	aescbc, err := aes.NewAES(types.ModeCBC, "", "my-password", types.Base64)
	require.Nil(t, err)

	plain := "hello world @ 2020"
	ciphertext, err := aescbc.EncryptText(plain, "")
	require.Nil(t, err)

	decrypted, err := aescbc.DecryptText(ciphertext, "")
	require.Nil(t, err)
	require.Equal(t, plain, decrypted)
}

func TestCBCFile(t *testing.T) {
	aescbc, err := aes.NewAES(types.ModeCBC, "", "my-password", types.Base64)
	require.Nil(t, err)

	err = aescbc.EncryptFile("../testdata/xxy007.png", "../testdata/xxy007.png.cbc", "")
	require.Nil(t, err)

	err = aescbc.DecryptFile("../testdata/xxy007.png.cbc", "../testdata/xxy007.cbc.png", "")
	require.Nil(t, err)
}

func TestGCMFile(t *testing.T) {
	aesgcm, err := aes.NewAES("gcm", "", "my-password", types.Base64)
	require.Nil(t, err)

	err = aesgcm.EncryptFile("../testdata/xxy007.png", "../testdata/xxy007.png.gcm", "")
	require.Nil(t, err)

	err = aesgcm.DecryptFile("../testdata/xxy007.png.gcm", "../testdata/xxy007.gcm.png", "")
	require.Nil(t, err)
}

func TestGCMPadding(t *testing.T) {
	aesgcm, err := aes.NewAES("gcm", "", "my-password", types.Base64)
	require.Nil(t, err)

	for i := 1; i <= 17; i++ {
		ciphertext, err := aesgcm.EncryptBytes(make([]byte, i), "")
		require.Nil(t, err)
		require.Equal(t, 16, len(ciphertext)-14-i)
	}
}

func TestFilePath(t *testing.T) {
	files, err := ioutil.ReadDir("../testdata")
	require.Nil(t, err)

	for _, file := range files {
		fmt.Println(file.Name())
	}
}

func TestNewKey(t *testing.T) {
	key, err := aes.NewKey(256)
	require.Nil(t, err)

	keyBuf, err := base64.StdEncoding.DecodeString(key)
	require.Nil(t, err)
	require.Equal(t, 32, len(keyBuf))
}
