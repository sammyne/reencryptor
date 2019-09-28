// +build ignore

package main

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/cloudflare/bn256"
)

var Z *bn256.GT

func init() {
	// generator for group 1
	g1 := new(bn256.G1).ScalarBaseMult(big.NewInt(1))

	// generator for group 2
	g2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))

	Z = bn256.Pair(g1, g2)
}

func reciprocal(x *big.Int) *big.Int {
	return new(big.Int).ModInverse(x, bn256.Order)
}

func encrypt(msg *bn256.GT, Y *bn256.G1) (*bn256.GT, *bn256.G1, *big.Int, error) {
	r, _, err := bn256.RandomG2(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	rZ := new(bn256.GT).ScalarMult(Z, r)
	rY := new(bn256.G1).ScalarMult(Y, r)

	return new(bn256.GT).Add(rZ, msg), rY, r, nil
}

func reDecrypt(ciphertext, C2 *bn256.GT, x *big.Int) *bn256.GT {
	xInv := reciprocal(x)

	rZ := new(bn256.GT).ScalarMult(C2, xInv)

	return new(bn256.GT).Add(ciphertext, rZ.Neg(rZ))
}

func main() {
	// Alice
	a, A, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		panic(err)
	}

	_, msg, err := bn256.RandomGT(rand.Reader)
	if err != nil {
		panic(err)
	}
	//fmt.Println("plaintext =", msg)

	// first-level encryption to store in server
	C11, C12, r, err := encrypt(msg, A)
	if err != nil {
		panic(err)
	}
	//fmt.Println("Z =", Z)
	rZ := new(bn256.GT).ScalarMult(Z, r)
	v := new(bn256.GT).Neg(rZ)
	v = v.Add(v, C11)
	fmt.Println("1", v.String() == msg.String())

	// then delivers Bob public key to Alice
	b, B, err := bn256.RandomG2(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Alice
	// calculate re-encryption key x^{-1}*B=x*B^{-1}
	//BInv := new(bn256.G2).Neg(B)
	//reEncryptionKey := BInv.ScalarMult(BInv, a)

	//aInv := new(big.Int).ModInverse(a, bn256.Order)
	aInv := reciprocal(a)
	reEncryptionKey := new(bn256.G2).ScalarMult(B, aInv)
	//aa := aInv.Mul(aInv, a)
	//aa.Mod(aa, bn256.Order)
	//fmt.Println("aa =", aa)
	//fmt.Println("RK1 =", reEncryptionKey)

	//aInv := new(big.Int).Add(bn256.Order, new(big.Int).Neg(a))
	//RK2 := new(bn256.G2).ScalarMult(B, aInv)
	//fmt.Println("RK2 =", RK2)

	// proxy side
	C2 := bn256.Pair(C12, reEncryptionKey)
	fmt.Println("C2 =", C2)

	rb := new(big.Int).Mul(r, b)
	rb.Mod(rb, bn256.Order)
	c2 := new(bn256.GT).ScalarBaseMult(rb)
	fmt.Println("c2 =", c2)
	fmt.Println("C2 == c2 ?", C2.String() == c2.String())

	//vv := new(big.Int).Set(r)
	//vv = vv.Add(vv)

	msg2 := reDecrypt(C11, C2, b)
	//fmt.Println("recovered =", msg2)
	fmt.Println("recovered == msg ?", msg2.String() == msg.String())
	//fmt.Println("Z =", Z)
}
