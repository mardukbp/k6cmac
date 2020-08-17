package k6cmac

import (
	"context"
	"crypto/aes"
	"encoding/base64"
	"github.com/aead/cmac"
)

type K6cmac struct{}

func New() *K6cmac {
	return &K6cmac{}
}

// Method names must begin with a capital letter
func (c *K6cmac) Generatecmac(ctx context.Context, keyb64 string, data string) string {
	key, _ := base64.StdEncoding.DecodeString(keyb64)
	aesCipher, _ := aes.NewCipher(key)
	signature, _ := cmac.Sum([]byte(data), aesCipher, 8)
	return base64.StdEncoding.EncodeToString(signature)
}
