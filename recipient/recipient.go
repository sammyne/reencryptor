package recipient

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/cloudflare/bn256"
	"github.com/sammyne/reencryptor"
)

type PrivateKey struct {
	PublicKey

	D *big.Int
}

type PublicKey struct {
	Curve reencryptor.BN256
	Point *bn256.G2
}

func ReDecrypt(ciphertext []byte, reEncryptedTag []byte, priv *PrivateKey) ([]byte, error) {
	cP := new(bn256.GT)
	if _, err := cP.Unmarshal(ciphertext); err != nil {
		return nil, err
	}

	tagP := new(bn256.GT)
	if _, err := tagP.Unmarshal(reEncryptedTag); err != nil {
		return nil, err
	}

	dInv := priv.Curve.Reciporocal(priv.D)

	rZ := new(bn256.GT).ScalarMult(tagP, dInv)

	M := new(bn256.GT).Add(cP, rZ.Neg(rZ))

	return M.Marshal(), nil
}

func GenerateKey(curve reencryptor.Curve, reader io.Reader) (*PrivateKey, error) {
	bn256Curve, ok := curve.(reencryptor.BN256)
	if !ok {
		return nil, errors.New("only curve bn256 is supported now")
	}

	d, XY, err := bn256.RandomG2(rand.Reader)
	if err != nil {
		return nil, err
	}

	priv := &PrivateKey{
		PublicKey: PublicKey{
			Curve: bn256Curve,
			Point: XY,
		},
		D: d,
	}

	return priv, nil
}
