package cryptopals

import (
	"bytes"
	"crypto/md5"
	"encoding/asn1"
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
	// Instead of finding large primes ourselves, we'll use OpenSSL. Start with 1024-bit
	// primes, which gives us 2048-bit RSA keys.
	fmt.Println("$ openssl prime -generate -bits 1024 -hex")
	pOut, _ := exec.Command("openssl", "prime", "-generate", "-bits", "1024", "-hex").Output()
	pBytes, _ := hex.DecodeString(string(pOut))
	qOut, _ := exec.Command("openssl", "prime", "-generate", "-bits", "1024", "-hex").Output()
	qBytes, _ := hex.DecodeString(string(qOut))

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

/*
	RSA Padding: https://tools.ietf.org/html/rfc2313

	A block type BT, a padding string PS, and the data D shall be
	formatted into an octet string EB, the encryption block.

			EB = 00 || BT || PS || 00 || D .           (1)

	The block type BT shall be a single octet indicating the structure of
	the encryption block. For this version of the document it shall have
	value 00, 01, or 02. For a private- key operation, the block type
	shall be 00 or 01. For a public-key operation, it shall be 02.

	The padding string PS shall consist of k-3-||D|| octets. For block
	type 00, the octets shall have value 00; for block type 01, they
	shall have value FF; and for block type 02, they shall be
	pseudorandomly generated and nonzero. This makes the length of the
	encryption block EB equal to k.
*/

// RSAPad pads data using PKCS1.5. 'k' is the length of the modulus
// in octects.
func RSAPad(k int, blockType byte, data []byte) []byte {
	paddedData := make([]byte, k) // zero initialized
	paddedData[1] = blockType
	copy(paddedData[k-len(data):], data)

	if blockType == 1 {
		copy(paddedData[2:], bytes.Repeat([]byte{0xFF}, k-3-len(data)))
	}

	if blockType == 2 {
		panic("method not implemented")
	}

	return paddedData
}

/*
	RSA Signatures: https://tools.ietf.org/html/rfc2313

	10.1
	The signature process consists of four steps: message digesting, data
	encoding, RSA encryption, and octet-string-to-bit-string conversion.
	The input to the signature process shall be an octet string M, the
	message; and a signer's private key. The output from the signature
	process shall be a bit string S, the signature.

	DigestInfo ::= SEQUENCE {
		digestAlgorithm DigestAlgorithmIdentifier,
		digest Digest }

	DigestAlgorithmIdentifier ::= AlgorithmIdentifier

	Digest ::= OCTET STRING

	digestAlgorithm identifies the message-digest algorithm (and any associated parameters). For
	this application, it should identify the selected message-digest algorithm, MD2, MD4 or MD5. For
	reference, the relevant object identifiers are the following:

	md2 OBJECT IDENTIFIER ::= { iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) 2 }
	md4 OBJECT IDENTIFIER ::= { iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) 4 }
	md5 OBJECT IDENTIFIER ::= { iso(1) member-body(2) US(840) rsadsi(113549) digestAlgorithm(2) 5 }
*/

type RSADigest struct {
	DigestAlgorithm asn1.ObjectIdentifier
	Digest          []byte
}

func RSASignMessage(message []byte, priv *RSAKey) ([]byte, error) {
	md := md5.Sum(message)
	asnDigest := RSADigest{
		DigestAlgorithm: asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 2, 5}),
		Digest:          md[:],
	}

	d, err := asn1.Marshal(asnDigest)
	if err != nil {
		return nil, fmt.Errorf("could not marshall digest: %w", err)
	}

	// Length of modulus in octets
	k := len(priv.N.Bytes())

	// Encryption Block (RFC 2313: Section 8.1)
	eb := RSAPad(2048, 1, d)

	// Octet-to-integer conversion (Section 8.2)
	sum := big.NewInt(0)
	for i := 1; i <= k; i++ {
		p := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(8*(k-i))), big.NewInt(0))
		sum.Add(sum, new(big.Int).Mul(p, big.NewInt(int64(eb[i-1]))))
	}

	// Encrypt
	ed := RSAEncrypt(sum, priv).Bytes()
	return ed, nil
}
