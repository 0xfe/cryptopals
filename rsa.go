package cryptopals

/*
## Cryptopals Solutions by Mohit Muthanna Cheppudira 2020.

Implementation of RSA encryption, padding, and signatures. Used by multiple Cryptopals challenges.
*/

import (
	"bytes"
	"crypto/md5"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
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
func RSAGenKeyPair(bitLen int) *RSAKeyPair {
	p := generatePrime(bitLen / 2)
	q := generatePrime(bitLen / 2)

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

// Encrypt encrypts message with public key pub
func (key *RSAKey) Encrypt(message *big.Int) *big.Int {
	return bigModExp(message, key.v, key.N)
}

// Decrypt decrypts cipher with private key priv
func (key *RSAKey) Decrypt(cipher *big.Int) *big.Int {
	return bigModExp(cipher, key.v, key.N)
}

// EncryptString encrypts string message with public key pub
func (key *RSAKey) EncryptString(message string) string {
	return key.Encrypt(new(big.Int).SetBytes([]byte(message))).Text(16)
}

// DecryptString decrypts string message with public key pub
func (key *RSAKey) DecryptString(message string) string {
	v, _ := new(big.Int).SetString(message, 16)
	return string(key.Decrypt(v).Bytes())
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
// in octects (1024-bit RSA = 128)
func RSAPad(k int, blockType byte, data []byte) []byte {
	paddedData := make([]byte, k) // zero initialized
	paddedData[1] = blockType
	copy(paddedData[k-len(data):], data)

	if blockType == 1 {
		copy(paddedData[2:], bytes.Repeat([]byte{0xFF}, k-3-len(data)))
	}

	if blockType == 2 {
		// Fill with random non-zero bytes
		for i := 0; i < k-3-len(data); i++ {
			for paddedData[2+i] == 0 {
				paddedData[2+i] = byte(rand.Int())
			}
		}
	}

	return paddedData
}

// RSAUnpad removes the padding from paddedData and returns the embedded
// data. Note that paddedData must be zero-padded with length k.
func RSAUnpad(paddedData []byte) []byte {
	if paddedData[0] != 0 {
		return nil
	}

	fillByte := byte(0)
	if paddedData[1] == 1 {
		fillByte = 0xff
	}
	if paddedData[1] == 2 {
		fillByte = 0x03
	}
	start := 0
	for i := 2; i < len(paddedData); i++ {
		if paddedData[i] == 0 {
			start = i + 1
			break
		}

		if fillByte != 0x03 && paddedData[i] != fillByte {
			return nil
		}
	}

	return paddedData[start:]
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

// RSADigest is the ASN.1 wire-representation of RSA signatures.
type RSADigest struct {
	DigestAlgorithm asn1.ObjectIdentifier
	Digest          []byte
}

// Sign 'message' with private-key 'key' returning wire-ready signature.
func (key *RSAKey) Sign(message []byte) ([]byte, error) {
	// Take MD5 hash of message and encode it into an ASN.1 blob
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
	k := len(key.N.Bytes())

	// Pad and create encryption Block (RFC 2313: Section 8.1)
	eb := RSAPad(k, 1, d)

	// Convert octet-string to integer (RFC 2313: Section 8.2)
	sum := big.NewInt(0)
	for i := 1; i <= k; i++ {
		p := new(big.Int).Exp(big.NewInt(256), big.NewInt(int64(k-i)), big.NewInt(0))
		sum.Add(sum, new(big.Int).Mul(p, big.NewInt(int64(eb[i-1]))))
	}

	// Encrypt and return byte-representation of integer value
	ed := key.Encrypt(sum).Bytes()
	return ed, nil
}

// Verify that 'message' is signed with 'sig'. 'key' should be the signer's public key.
func (key *RSAKey) Verify(message []byte, sig []byte) (bool, error) {
	// Constant time integer-to-octet conversion: https://tools.ietf.org/html/rfc8017#section-4.1
	// Copied from https://github.com/mozilla-services/go-cose/blob/master/core.go
	i2osp := func(b *big.Int, n int) []byte {
		octetString := b.Bytes()
		octetStringSize := len(octetString)
		result := make([]byte, n)

		if !(b.Sign() == 0 || b.Sign() == 1) {
			panic("i2osp error: integer must be zero or positive")
		}
		if n == 0 || octetStringSize > n {
			panic("i2osp error: integer too large")
		}

		subtle.ConstantTimeCopy(1, result[:n-octetStringSize], result[:n-octetStringSize])
		subtle.ConstantTimeCopy(1, result[n-octetStringSize:], octetString)
		return result
	}

	// Convert sig to integer value and decrypt
	sum := new(big.Int).SetBytes(sig)
	ed := key.Decrypt(sum)

	// Convert decrypted integer to string
	paddedData := i2osp(ed, len(key.N.Bytes()))

	// PKCS1.5 unpad
	d := RSAUnpad(paddedData)
	if d == nil {
		return false, fmt.Errorf("could not unpad data")
	}

	// Extract ASN.1 blob with MD5 signature
	asnDigest := RSADigest{}
	_, err := asn1.Unmarshal(d, &asnDigest)
	if err != nil {
		return false, fmt.Errorf("could not unmarshall digest: %w", err)
	}

	fmt.Println("digest", asnDigest.DigestAlgorithm.String())
	fmt.Println("digest", hex.EncodeToString(asnDigest.Digest))

	// Validate that MD5 hash of message matches hash in signature
	md := md5.Sum(message)
	fmt.Println("md", hex.EncodeToString(md[:]))
	return bytes.Equal(md[:], asnDigest.Digest), nil
}
