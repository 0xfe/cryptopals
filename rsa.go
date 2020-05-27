package cryptopals

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os/exec"
)

// RSAKey represents a single public or private key
type RSAKey struct {
	N *big.Int
	v *big.Int
}

// RSAKeyPair represents an RSA key pair
type RSAKeyPair struct {
	Pub  *RSAKey
	Priv *RSAKey
}

// RSAGenKeyPair generates a new RSA key pair
func RSAGenKeyPair() *RSAKeyPair {
	// Instead of finding large primes ourselves, we'll use OpenSSL
	fmt.Println("$ openssl prime -generate -bits 2048 -hex")
	pOut, _ := exec.Command("openssl", "prime", "-generate", "-bits", "2048", "-hex").Output()
	pBytes, _ := hex.DecodeString(string(pOut))
	qOut, _ := exec.Command("openssl", "prime", "-generate", "-bits", "2048", "-hex").Output()
	qBytes, _ := hex.DecodeString(string(qOut))

	// These should be auto generated
	//
	// $ openssl prime -generate -bits 2048 -hex
	p := new(big.Int).SetBytes(pBytes)
	q := new(big.Int).SetBytes(qBytes)

	nbi := func() *big.Int { return new(big.Int) }
	n := nbi().Mul(p, q)
	et := nbi().Mul(nbi().Sub(p, big.NewInt(1)), nbi().Sub(q, big.NewInt(1)))
	e := big.NewInt(3)
	d := nbi().ModInverse(e, et)

	return &RSAKeyPair{
		Pub:  &RSAKey{n, e},
		Priv: &RSAKey{n, d},
	}
}

// RSAEncrypt encrypts message with public key pub
func RSAEncrypt(message *big.Int, pub *RSAKey) *big.Int {
	return bigModExp(message, pub.v, pub.N)
}

// RSADecrypt decrypts cipher with private key priv
func RSADecrypt(cipher *big.Int, priv *RSAKey) *big.Int {
	return bigModExp(cipher, priv.v, priv.N)
}

// RSAEncryptString encrypts string message with public key pub
func RSAEncryptString(message string, pub *RSAKey) string {
	return RSAEncrypt(new(big.Int).SetBytes([]byte(message)), pub).Text(16)
}

func RSADecryptString(message string, priv *RSAKey) string {
	v, _ := new(big.Int).SetString(message, 16)
	return string(RSADecrypt(v, priv).Bytes())
}
