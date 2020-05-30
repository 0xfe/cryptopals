package cryptopals

import (
	"crypto/md5"
	"encoding/asn1"
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

func TestS6C42(t *testing.T) {
	keyPair := RSAGenKeyPair()

	// Test sign and verify with PKCS1.5 padding and ASN.1 digest
	sig, err := RSASignMessage([]byte("foobar"), keyPair.Priv)
	assertNoError(t, err)
	success, err := RSAVerifySignature([]byte("foobar"), sig, keyPair.Pub)
	assertNoError(t, err)
	assertTrue(t, success)

	// Forge "hi mom" and check that it verifies with an abitrary keypair.
	message := []byte("hi mom")

	// Take MD5 hash of message and encode it into an ASN.1 blob.
	md := md5.Sum(message)
	asnDigest := RSADigest{
		DigestAlgorithm: asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 2, 5}),
		Digest:          md[:],
	}

	d, err := asn1.Marshal(asnDigest)
	assertNoError(t, err)

	// Length of modulus in octets (used for padding). This is equivalent to the RSA
	// block size (for the respective key size.)
	k := len(keyPair.Priv.N.Bytes())

	// Add a whole bunch of garbage 0-s at the end (up to length k) so RSAPad has almost
	// no extra padding to add.
	forgedMessage := append(d, make([]byte, k-3-(len(d)))...)

	// Add a few 1-bytes immediately after the data to accomodate for the cube root remainder,
	// since we very likely won't end up with a perfect cube.
	copy(forgedMessage[len(d):], []byte{1, 1, 1})

	// Pad and create encryption Block (RFC 2313: Section 8.1) formatted for RSAVerify
	eb := RSAPad(k, 1, forgedMessage)

	// Convert octet-string to integer (RFC 2313: Section 8.2)
	sum := big.NewInt(0)
	for i := 1; i <= k; i++ {
		p := new(big.Int).Exp(big.NewInt(256), big.NewInt(int64(k-i)), big.NewInt(0))
		sum.Add(sum, new(big.Int).Mul(p, big.NewInt(int64(eb[i-1]))))
	}

	// Instead of signing the message, we take the cube root of the message.
	// Assuming e=3, this should result in a value that does not wrap the modulus, which makes
	// (d, N) ineffective. The verification process cubes the message (again, because e=3) as
	// part of RSADecrypt (with public key).
	//
	// Note that cubeRoot returns a remainder incase sum is not a perfect cube.
	sumCubeRt, _ := cubeRoot(sum)

	success, err = RSAVerifySignature(message, sumCubeRt.Bytes(), keyPair.Pub)
	assertNoError(t, err)
	assertTrue(t, success)
}

func TestS6C43(t *testing.T) {
	// Test that DSA signing and verification works.

	// Generate a DSA keypair
	priv, pub, err := DSAGenKeyPair()
	assertNoError(t, err)

	// Message from challenge 43
	message := []byte("For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n")

	// Sign with private key
	sig, err := priv.Sign(message)
	assertNoError(t, err)

	// Verify with public key
	valid, err := pub.Verify(message, sig)
	assertNoError(t, err)
	assertTrue(t, valid)
}
