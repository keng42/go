package types

// AES interface used to provide a unified list of methods for aes-gcm and aes-cbc
type AES interface {
	EncryptBytes(plain []byte, password string) ([]byte, error)
	DecryptBytes(cipher []byte, password string) ([]byte, error)
	EncryptText(plain string, password string) (string, error)
	DecryptText(cipher string, password string) (string, error)
	EncryptFile(src, dst, password string) error
	DecryptFile(src, dst, password string) error
}

type ModeType string
type EncodingType string

// Constants used to limit NewAES's parameter values
const (
	ModeGCM    ModeType     = "gcm"
	ModeCBC    ModeType     = "cbc"
	Base64     EncodingType = "base64"
	Hex        EncodingType = "hex"
	DefaultKey string       = "7At16p/dyonmDW3ll9Pl1bmCsWEACxaIzLmyC0ZWGaE="
)

const (
	GcmNonceSize   = 12        // standard nonce length for gcm mode
	GmcAuthTagSize = 16        // default auth tag length for gcm mode
	CbcIVSize      = 16        // standard iv length for cbc mode
	FileBufferSize = 16 * 1024 // default buffer size when reading file
)
