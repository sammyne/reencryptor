package reencryptor

import (
	"math/big"

	"github.com/cloudflare/bn256"
)

type Curve = interface{}

type BN256 struct {
	Z *bn256.GT
}

func (curve BN256) Reciporocal(x *big.Int) *big.Int {
	return new(big.Int).ModInverse(x, bn256.Order)
}

func NewBN256() Curve {
	// generator for group 1
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))

	// generator for group 2
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))

	return BN256{
		Z: bn256.Pair(g1, g2),
	}
}
