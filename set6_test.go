package cryptopals

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"
)

func TestS6C41(t *testing.T) {
	keyPair := RSAGenKeyPair()

	message := big.NewInt(42)

	c := RSAEncrypt(message, keyPair.Pub)
	fmt.Println("c:", c.Text(10))

	// Modify c (using public N and v) to create C'
	e := keyPair.Pub.v
	N := keyPair.Pub.N
	s := bigModExp(big.NewInt(rand.Int63()+1), big.NewInt(1), N)
	fmt.Println("s:", s.Text(10))
	cPrime := new(big.Int).Mod(new(big.Int).Mul(bigModExp(s, e, N), c), N)
	fmt.Println("cPrime:", cPrime.Text(10))

	// Decrypt C' using private key (assume C' is sent to a server to decrypt)
	pPrime := RSADecrypt(cPrime, keyPair.Priv)
	fmt.Println("pPrime:", pPrime.Text(10))
	pPrimeOverS := new(big.Int).Mul(pPrime, new(big.Int).ModInverse(s, N))
	p := new(big.Int).Mod(pPrimeOverS, N)
	fmt.Println("Recovered Plaintext:", p.Text(10))

	assertEquals(t, message.Int64(), p.Int64())
}
