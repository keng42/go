// AES used to encrypt/decrypt text or file using aes-gcm or aes-cbc
//
// created by keng42 @2020-12-04 10:30:05
//

package aes

import (
	"encoding/base64"
	"errors"

	"github.com/keng42/go/cnigma/aes/cbc"
	"github.com/keng42/go/cnigma/aes/gcm"
	"github.com/keng42/go/cnigma/aes/types"
	"github.com/keng42/go/cnigma/aes/utils"
)

// NewAES returns a GCM or CBC instance depending on the mode parameter.
// It's provide default value for all parameters except for the password in gcm mode.
func NewAES(
	mode types.ModeType,
	key string,
	password string,
	encoding types.EncodingType,
) (types.AES, error) {

	if mode == "" {
		mode = types.ModeGCM
	}
	if mode == types.ModeGCM && password == "" {
		return nil, errors.New("password is required in gcm mode")
	}
	if mode != types.ModeGCM && mode != types.ModeCBC {
		return nil, errors.New("only support gcm and cbc mode")
	}

	if key == "" {
		key = types.DefaultKey
	}
	keyBuf, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	keySize := len(keyBuf) * 8
	if keySize != 256 {
		if mode == types.ModeCBC {
			return nil, errors.New("key requires a 256-bit base64 encoded string with cbc mode")
		}
		if keySize != 128 && keySize != 192 {
			return nil, errors.New("key requires a 128-bit, 192-bit or 256-bit base64 encoded string")
		}
	}

	if encoding == "" {
		encoding = types.Base64
	}

	if mode == types.ModeGCM {
		return &gcm.GCM{
			Key:      keyBuf,
			Password: password,
			Version:  []byte{0x01, 0x03},
			Encoding: encoding,
		}, nil
	}
	return &cbc.CBC{
		Key:      keyBuf,
		Version:  []byte{0x01, 0x04},
		Encoding: encoding,
	}, nil
}

// NewGCM returns a GCM instance
func NewGCM(
	key string,
	password string,
	encoding types.EncodingType,
) (types.AES, error) {
	return NewAES(types.ModeGCM, key, password, encoding)
}

// NewCBC returns a CBC instance
func NewCBC(
	key string,
	encoding types.EncodingType,
) (types.AES, error) {
	return NewAES(types.ModeCBC, key, "", encoding)
}

func NewKey(size int) (string, error) {
	if size == 0 {
		size = 256
	}
	if size != 128 && size != 192 && size != 256 {
		return "", errors.New("key size allow 128-bit, 192-bit or 256-bit only")
	}

	buf, err := utils.RandomBytes(size / 8)
	if err != nil {
		return "", err
	}
	s := base64.StdEncoding.EncodeToString(buf)

	return s, nil
}
