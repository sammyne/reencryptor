package proxy

import (
	"github.com/cloudflare/bn256"
)

func ReEncrypt(tag []byte, reEncryptionKey []byte) ([]byte, error) {
	tagP := new(bn256.G1)
	if _, err := tagP.Unmarshal(tag); err != nil {
		return nil, err
	}

	reEncryptionKeyP := new(bn256.G2)
	if _, err := reEncryptionKeyP.Unmarshal(reEncryptionKey); err != nil {
		return nil, err
	}

	return bn256.Pair(tagP, reEncryptionKeyP).Marshal(), nil
}
