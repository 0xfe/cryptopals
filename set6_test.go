package cryptopals

/*
## Cryptopals Solutions by Mohit Muthanna Cheppudira 2020.

This file consists of solutions to Set 6.
*/

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func TestS6C41(t *testing.T) {
	keyPair := RSAGenKeyPair(2048)

	message := big.NewInt(42)

	c := keyPair.Pub.Encrypt(message)
	fmt.Println("c:", c.Text(10))

	// Modify c (using public N and v) to create C'
	e := keyPair.Pub.v
	N := keyPair.Pub.N
	s := bigModExp(big.NewInt(rand.Int63()+1), big.NewInt(1), N)
	fmt.Println("s:", s.Text(10))
	cPrime := new(big.Int).Mod(new(big.Int).Mul(bigModExp(s, e, N), c), N)
	fmt.Println("cPrime:", cPrime.Text(10))

	// Decrypt C' using private key (assume C' is sent to a server to decrypt)
	pPrime := keyPair.Priv.Decrypt(cPrime)
	fmt.Println("pPrime:", pPrime.Text(10))
	pPrimeOverS := new(big.Int).Mul(pPrime, new(big.Int).ModInverse(s, N))
	p := new(big.Int).Mod(pPrimeOverS, N)
	fmt.Println("Recovered Plaintext:", p.Text(10))

	assertEquals(t, message.Int64(), p.Int64())
}

func TestS6C42(t *testing.T) {
	keyPair := RSAGenKeyPair(2048)

	// Test sign and verify with PKCS1.5 padding and ASN.1 digest
	sig, err := keyPair.Priv.Sign([]byte("foobar"))
	assertNoError(t, err)
	success, err := keyPair.Pub.Verify([]byte("foobar"), sig)
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
	sumCubeRt, _ := bigCubeRt(sum)

	success, err = keyPair.Pub.Verify(message, sumCubeRt.Bytes())
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

	// Crypotopals challenge: Recover private key from y (public key), given signature
	r, success := new(big.Int).SetString("548099063082341131477253921760299949438196259240", 10)
	assertTrue(t, success)
	s, success := new(big.Int).SetString("857042759984254168557880549501802188789837994940", 10)
	assertTrue(t, success)

	nbi := func() *big.Int { return new(big.Int) }
	hBytes := sha1.Sum(message)
	h := nbi().SetBytes(hBytes[:])

	// Recover private key by trying all k-values from 0 - 2^16. The SHA1 of the private key is xSHA1
	xSHA1, err := hex.DecodeString("0954edd5e0afe5542a4adf012611a91912a3ec16")
	assertNoError(t, err)
	var priv2 *DSAKey
	for i := 0; i < int(math.Pow(2, 16)); i++ {
		k := nbi().SetInt64(int64(i))
		if nbi().ModInverse(k, priv.q) == nil {
			// If there's no inverse for k (modulo q), then skip
			continue
		}

		// Construct a private key out of k, r, s, and h (modulo q)
		x := nbi().Mod(nbi().Mul(nbi().Sub(nbi().Mul(s, k), h), nbi().ModInverse(r, priv.q)), priv.q)
		priv2 = &DSAKey{
			p:   priv.p,
			q:   priv.q,
			g:   priv.g,
			key: x,
		}
		sig2, err := priv2.Sign(message, map[string]*big.Int{
			"k": k,
		})
		assertNoError(t, err)
		if sig2.r.Cmp(r) == 0 && sig2.s.Cmp(s) == 0 {
			xSum := sha1.Sum([]byte(x.Text(16)))
			assertTrue(t, bytes.Equal(xSum[:], xSHA1))
			break
		}
	}

	// Verify that the public key can verify messages signed by our cracked private key
	y, success := nbi().SetString("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16)
	assertTrue(t, success)
	pub2 := &DSAKey{
		p:   priv.p,
		q:   priv.q,
		g:   priv.g,
		key: y,
	}

	message = []byte("foobar")
	sig, err = priv2.Sign(message) // , map[string]*big.Int{"kMax": big.NewInt(65535)})
	assertNoError(t, err)

	valid, err = pub2.Verify(message, sig)
	assertNoError(t, err)
	assertTrue(t, valid)
}

func TestS6C44(t *testing.T) {
	data, err := ioutil.ReadFile("data/44.txt")
	assertNoError(t, err)
	type S struct {
		msg string
		s   *big.Int
		r   *big.Int
		m   *big.Int
	}

	lines := strings.Split(string(data), "\n")
	msgs := []*S{}
	nbi := func() *big.Int { return new(big.Int) }

	el := &S{}
	for i, line := range lines {
		switch i % 4 {
		case 0:
			// Line 1 is the message string
			el.msg = line[5:]
		case 1:
			// Line 2 is 's' of signature
			v, success := new(big.Int).SetString(line[3:], 10)
			assertTrue(t, success)
			el.s = v
		case 2:
			// Line 3 is 'r' of signature
			v, success := new(big.Int).SetString(line[3:], 10)
			assertTrue(t, success)
			el.r = v
		case 3:
			// Line 4 is the SHA1 hash of the message
			v, success := nbi().SetString(zeroPad(line[3:]), 16)
			assertTrue(t, success)
			el.m = v
			msgs = append(msgs, el)
			el = &S{}
		}
	}

	for _, m := range msgs {
		sum := sha1.Sum([]byte(m.msg))
		fmt.Println(zeroPad(m.m.Text(16)), hex.EncodeToString(sum[:]))
	}

	_, priv, err := DSAGenKeyPair()
	assertNoError(t, err)

	y, success := nbi().SetString("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", 16)
	assertTrue(t, success)

	pub2 := &DSAKey{
		p:   priv.p,
		q:   priv.q,
		g:   priv.g,
		key: y,
	}

	message := []byte("foobar")
	var priv2 *DSAKey
	var cracked bool

	// Test to see if a nonce (k) was repeated between any pair of messages in the file. If
	// k was reused, it is easy to recover the private key (x) from the messages + signatures.
	for _, m1 := range msgs {
		for _, m2 := range msgs {
			// Construct a k from m1 and m2
			m := nbi().Mod(nbi().Sub(m1.m, m2.m), priv.q) // (m1 - m2) mod q
			s := nbi().Mod(nbi().Sub(m1.s, m2.s), priv.q) // (s1 - s2) mod q
			if nbi().ModInverse(s, priv.q) == nil {
				// If there's no inverse for s (modulo q), then skip
				continue
			}

			// (m * modinv(s)) mod q
			k := nbi().Mod(nbi().Mul(m, nbi().ModInverse(s, priv.q)), priv.q)
			if nbi().ModInverse(k, priv.q) == nil {
				// If there's no inverse for k (modulo q), then skip
				continue
			}

			fmt.Println("Using k", k.Text(16))

			// Construct a private key (x) out of k, r, s, and h (modulo q), using message 1 (m1). We could
			// also use message 2 here, but that doesn't matter. This is the same equation as the previous
			// challenge.
			h := m1.m
			r := m1.r
			x := nbi().Mod(nbi().Mul(nbi().Sub(nbi().Mul(m1.s, k), h), nbi().ModInverse(r, priv.q)), priv.q)
			priv2 = &DSAKey{
				p:   priv.p,
				q:   priv.q,
				g:   priv.g,
				key: x,
			}

			// Sign a message with this new private key
			sig2, err := priv2.Sign(message, map[string]*big.Int{
				"k": k,
			})
			assertNoError(t, err)

			// Verify the message with the Cryptopals public key
			valid, err := pub2.Verify(message, sig2)
			assertNoError(t, err)

			if valid {
				fmt.Println("Cracked! DSA private key (x):", priv2.key.Text(16))
				cracked = true
				break
			}
		}

		if cracked {
			break
		}
	}

	// Assert that we found the private key
	assertTrue(t, cracked)

	// Assert the the private key hashes to the Cryptopals private key
	sum := sha1.Sum([]byte(priv2.key.Text(16)))
	assertEquals(t, "ca8f6f7c66fa362d40760d135b763eb8527d3d52", hex.EncodeToString(sum[:]))
}

func TestS6C45(t *testing.T) {
	// This will produce a bad signature (r == 0)
	priv, pub, err := DSAGenKeyPair(map[string]*big.Int{"g": big.NewInt(0)})
	assertNoError(t, err)

	message := []byte("foobar")
	sig, err := priv.Sign(message)

	// Validate that we receive an error
	_, err = pub.Verify(message, sig)
	assertHasError(t, err)

	// Create a keypair using p+1 as the generator ("g")
	p, success := new(big.Int).SetString(zeroPad("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1"), 16)
	assertTrue(t, success)

	pPlusOne := new(big.Int).Add(p, big.NewInt(1))
	priv, pub, err = DSAGenKeyPair(map[string]*big.Int{"p": p, "g": pPlusOne})

	// Sign message with p+1 key, notice that r==1 in signature
	sig, err = priv.Sign(message)
	fmt.Println(priv)

	// Validate sig against original message
	valid, err := pub.Verify(message, sig)
	assertNoError(t, err)
	assertTrue(t, valid)

	// Validate sig against arbitrary messages
	message2 := []byte("Hello, world")
	message3 := []byte("Goodbye, world")
	valid, err = pub.Verify(message2, sig)
	assertNoError(t, err)
	assertTrue(t, valid)

	valid, err = pub.Verify(message3, sig)
	assertNoError(t, err)
	assertTrue(t, valid)
}

func TestS6C46(t *testing.T) {
	keyPair := RSAGenKeyPair(1024)

	isEven := func(cipherText *big.Int, priv *RSAKey) bool {
		pt := priv.Decrypt(cipherText)
		if new(big.Int).Mod(pt, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
			return true
		}

		return false
	}

	// Unit-test isEven
	assertFalse(t, isEven(keyPair.Pub.Encrypt(big.NewInt(1)), keyPair.Priv))
	assertTrue(t, isEven(keyPair.Pub.Encrypt(big.NewInt(2)), keyPair.Priv))
	assertFalse(t, isEven(keyPair.Pub.Encrypt(big.NewInt(3)), keyPair.Priv))
	assertTrue(t, isEven(keyPair.Pub.Encrypt(big.NewInt(4)), keyPair.Priv))

	b64message := "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
	message, err := base64.StdEncoding.DecodeString(b64message)
	assertNoError(t, err)

	m := new(big.Int).SetBytes(message)
	ct := keyPair.Pub.Encrypt(m)

	// Set upper and lower bounds for message
	lb := big.NewInt(0)
	ub := keyPair.Pub.N

	fmt.Println("Cracking over 1024 iterations...")
	// Extract message a bit at a time for 1024-bits (log2(N)). See explanation here:
	//   https://crypto.stackexchange.com/questions/11053/rsa-least-significant-bit-oracle-attack
	for i := 0; i < 1024; i++ {
		// Double the cipherText
		ct = ct.Mod(new(big.Int).Mul(ct, keyPair.Pub.Encrypt(big.NewInt(2))), keyPair.Pub.N)
		if isEven(ct, keyPair.Priv) {
			// Plaintext did not wrap modulus, so was less than half the modulus
			ub = new(big.Int).Div(new(big.Int).Add(lb, ub), big.NewInt(2))
		} else {
			// Plaintext wrapped modulus, so was more than half the modulus
			lb = new(big.Int).Div(new(big.Int).Add(lb, ub), big.NewInt(2))
		}
	}

	fmt.Println("Cracked!", string(ub.Bytes()))
	assertTrue(t, bytes.Equal(message[:len(message)-2], ub.Bytes()[:len(message)-2]))
}

func Bleichenbacher98(t *testing.T, bits int) {
	fmt.Println("Starting Bleichenbacher98 attack. This might be slow.")
	rand.Seed(time.Now().UnixNano())
	nbi := func() *big.Int { return new(big.Int) }

	// Challenge 47 is limited to 256-bit RSA
	k := bits / 8

	// Generate an RSA Key pair
	keyPair := RSAGenKeyPair(bits)
	pub := keyPair.Pub
	priv := keyPair.Priv

	// This is our padding oracle, returns false if padding is bad
	isPadded := func(ct *big.Int) bool {
		pt := zeroPadBytes(priv.Decrypt(ct).Bytes())
		return pt[0] == 0 && pt[1] == 2
	}

	// Create our ciphertext to crack
	message := RSAPad(k, 2, []byte("kick it, CC"))
	m := nbi().SetBytes(message)
	c0 := pub.Encrypt(m)
	assertTrue(t, isPadded(c0))

	// Convenience constants
	n := pub.N
	B := nbi().Exp(big.NewInt(2), big.NewInt(int64(8*(k-2))), nil)
	Bx2 := nbi().Mul(big.NewInt(2), B)
	Bx3 := nbi().Mul(big.NewInt(3), B)

	type Range struct {
		a *big.Int
		b *big.Int
	}

	// Initialize ranges (starting range from paper)
	M := []Range{{a: Bx2, b: nbi().Sub(Bx3, big.NewInt(1))}}

	// Step 2a: search for the smallest positive integer s such that c*s is PKCS conforming
	si := bigCeilDiv(n, Bx3)
	var crackedMessage []byte
	for i := 1; crackedMessage == nil; i++ {
		fmt.Printf("starting round %d with len(M) %d\n", i, len(M))
		if i == 1 {
			fmt.Println("step 2.a si=", si.Text(10))
			for ; !isPadded(nbi().Mod(nbi().Mul(c0, pub.Encrypt(si)), n)); si.Add(si, big.NewInt(1)) {
			}
		} else {
			if len(M) == 1 {
				// If there's just one range
				a := M[0].a
				b := M[0].b

				ri := nbi().Mul(big.NewInt(2), bigCeilDiv(nbi().Sub(nbi().Mul(b, si), Bx2), n))
				fmt.Println(i, "step 2.c ri=", ri.Text(10))
				found := false

				for ; !found; ri.Add(ri, big.NewInt(1)) {
					si = bigCeilDiv(nbi().Add(Bx2, nbi().Mul(ri, n)), b)
					siMax := nbi().Div(nbi().Add(Bx3, nbi().Mul(ri, n)), a)

					for ; si.Cmp(siMax) <= 0; si.Add(si, big.NewInt(1)) {
						ci := nbi().Mod(nbi().Mul(c0, pub.Encrypt(si)), n)
						if isPadded(ci) {
							fmt.Println(i, "step 2.c: found si=", si.Text(10))
							found = true
							break
						}
					}
				}
			} else {
				// More than one range in M
				fmt.Println(i, "step 2.b si=", si.Text(10))
				for si = nbi().Add(si, big.NewInt(1)); !isPadded(nbi().Mod(nbi().Mul(c0, pub.Encrypt(si)), n)); si.Add(si, big.NewInt(1)) {
				}
			}
		}

		// Step 3: narrow set of solutions
		Mi := []Range{}
		fmt.Println(i, "step 3 len(M)=", len(M))
		for _, ran := range M {
			a := ran.a
			b := ran.b

			rMin := bigCeilDiv(nbi().Add(nbi().Sub(nbi().Mul(a, si), Bx3), big.NewInt(1)), n)
			rMax := nbi().Div(nbi().Sub(nbi().Mul(b, si), Bx2), n)

			fmt.Println(i, "step 3 narrowing rMin, rMax", rMin.Text(10), rMax.Text(10))
			for r := rMin; r.Cmp(rMax) != 1; r.Add(r, big.NewInt(1)) {
				fmt.Println(i, "step 3 narrowing r=", r.Text(10))
				newA := bigCeilDiv(nbi().Add(Bx2, nbi().Mul(r, n)), si)
				newB := bigFloorDiv(nbi().Add(nbi().Sub(Bx3, big.NewInt(1)), nbi().Mul(r, n)), si)
				newM := Range{bigMax(a, newA), bigMin(b, newB)}

				if newM.a.Cmp(newM.b) > 0 {
					continue
				}

				// Set union operation to merge intervals (poorly described in paper)
				done := false
				for i, mi := range Mi {
					if mi.b.Cmp(newM.a) < 0 {
						Mi = append(Mi, mi)
					} else if newM.b.Cmp(mi.a) < 0 {
						Mi = append(append(Mi, newM), Mi[i:]...)
						done = true
						break
					} else {
						newM = Range{a: bigMax(mi.a, newM.a), b: bigMin(mi.b, newM.b)}
					}
				}

				if !done {
					Mi = append(Mi, newM)
				}
			}
		}

		M = Mi

		// Step 4: Compute solution if
		if len(M) == 1 && M[0].a.Cmp(M[0].b) == 0 {
			crackedMessage = RSAUnpad(zeroPadBytes(M[0].a.Bytes()))
		}

		i++
	}

	fmt.Println("CRACKED:", string(crackedMessage))
	assertTrue(t, bytes.Equal(crackedMessage, RSAUnpad(zeroPadBytes(message))))
}

func TestS6C47(t *testing.T) {
	DISABLED := true

	if DISABLED {
		fmt.Println("Skipping disabled test S647: Bleichenbacher98 - 256. Very slooooow!")
		return
	}

	Bleichenbacher98(t, 256)
}

func TestS6C48(t *testing.T) {
	DISABLED := true

	if DISABLED {
		fmt.Println("Skipping disabled test S648: Bleichenbacher98 - 784. Very slooooow!")
		return
	}

	Bleichenbacher98(t, 768)
}
