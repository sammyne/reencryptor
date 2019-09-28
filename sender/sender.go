package sender

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/sammyne/reencryptor/recipient"

	"github.com/cloudflare/bn256"

	"github.com/sammyne/reencryptor"
)

type PrivateKey struct {
	PublicKey

	D *big.Int
}

type PublicKey struct {
	Curve reencryptor.BN256

	Point *bn256.G1
}

func DeriveReEncryptionKey(pub *recipient.PublicKey, priv *PrivateKey) []byte {
	dInv := priv.Curve.Reciporocal(priv.D)

	return new(bn256.G2).ScalarMult(pub.Point, dInv).Marshal()
}

// Encrypt encrypts with given msg
// @note the msg should be produced by reencryptor.NewEncryptableMessage()
func Encrypt(msg []byte, pub *PublicKey) ([]byte, []byte, error) {
	M := new(bn256.GT)
	if _, err := M.Unmarshal(msg); err != nil {
		return nil, nil, err
	}

	r, _, err := bn256.RandomG2(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	rZ := new(bn256.GT).ScalarMult(pub.Curve.Z, r)
	rY := new(bn256.G1).ScalarMult(pub.Point, r)

	return new(bn256.GT).Add(rZ, M).Marshal(), rY.Marshal(), nil
}

func GenerateKey(curve reencryptor.Curve, reader io.Reader) (*PrivateKey, error) {
	bn256Curve, ok := curve.(reencryptor.BN256)
	if !ok {
		return nil, errors.New("only curve bn256 is supported now")
	}

	d, XY, err := bn256.RandomG1(rand.Reader)
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
