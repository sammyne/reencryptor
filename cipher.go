package reencryptor

import (
	"io"

	"github.com/cloudflare/bn256"
)

func NewEncryptableMessage(rand io.Reader) ([]byte, error) {
	_, msg, err := bn256.RandomGT(rand)
	if err != nil {
		return nil, err
	}

	return msg.Marshal(), nil
}
