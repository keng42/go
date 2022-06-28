package types

type EncodingType string

const (
	Base64     EncodingType = "base64"
	Hex        EncodingType = "hex"
	DefaultKey string       = "7At16p/dyonmDW3ll9Pl1bmCsWEACxaIzLmyC0ZWGaE="
)

const (
	FileBufferSize = 16 * 1024 // default buffer size when reading file
)
