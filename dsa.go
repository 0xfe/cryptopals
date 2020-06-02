package cryptopals

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

type DSAKey struct {
	p   *big.Int
	q   *big.Int
	g   *big.Int
	key *big.Int // x or y (for private/public)
}

func (dk *DSAKey) String() string {
	return fmt.Sprintf("DSAKey:\n p = %s\n q = %s\n g = %s\n key = %s\n",
		dk.p.Text(16), dk.q.Text(16), dk.g.Text(16), dk.key.Text(16))
}

type DSASig struct {
	r *big.Int
	s *big.Int
}

func (sig *DSASig) String() string {
	return fmt.Sprintf("DSASig:\n r = %s\n s = %s\n", sig.r.Text(16), sig.s.Text(16))
}

// DSAGenKeyPair generates new DSA private and public keys. Parameter generation is not
// performed -- we use the parameters from Cryptopals Challenge 43
func DSAGenKeyPair(opts ...map[string]*big.Int) (priv *DSAKey, pub *DSAKey, err error) {
	p, success := new(big.Int).SetString(zeroPad("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1"), 16)
	if !success {
		return nil, nil, fmt.Errorf("could not generate prime p: %w", err)
	}

	q, success := new(big.Int).SetString(zeroPad("f4f47f05794b256174bba6e9b396a7707e563c5b"), 16)
	if !success {
		return nil, nil, fmt.Errorf("could not generate prime p: %w", err)
	}

	g, success := new(big.Int).SetString(zeroPad("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291"), 16)
	if !success {
		return nil, nil, fmt.Errorf("could not generate prime p: %w", err)
	}

	if len(opts) > 0 {
		// Allow overriding p, q, or g
		if pVal, ok := opts[0]["p"]; ok {
			p = pVal
		}
		if qVal, ok := opts[0]["q"]; ok {
			q = qVal
		}
		if gVal, ok := opts[0]["g"]; ok {
			g = gVal
		}
	}

	// Generate a random x between 1 and q-1
	x := new(big.Int).Rand(rand.New(rand.NewSource(time.Now().UnixNano())), new(big.Int).Sub(q, big.NewInt(2)))
	x = x.Add(x, big.NewInt(1))
	y := bigModExp(g, x, p)

	return &DSAKey{p: p, q: q, g: g, key: x}, &DSAKey{p: p, q: q, g: g, key: y}, nil
}

// Sign returns a signature for message signed with k
func (dk *DSAKey) Sign(message []byte, args ...map[string]*big.Int) (*DSASig, error) {
	// Generate a random k between 1 and q-1
	k := big.NewInt(0)
	r := big.NewInt(0)
	s := big.NewInt(0)

	nbi := func() *big.Int { return new(big.Int) }
	hBytes := sha1.Sum(message)
	h, success := nbi().SetString(hex.EncodeToString(hBytes[:]), 16)
	if !success {
		return nil, fmt.Errorf("could not hash message")
	}

	kMax := dk.q
	if len(args) > 0 {
		// Allow injecting h
		if hVal, ok := args[0]["h"]; ok {
			h = hVal
		}

		// Broken k
		if kMaxVal, ok := args[0]["kMax"]; ok {
			kMax = kMaxVal
		}
	}

	// Generate r and s from a random k, if r == 0 or s == 0, try again with a new random k
	// Challenge 45 tests broken signature implementations when "g" == 0, so we'll disable the
	// check if g == 0.
	for dk.g.Cmp(big.NewInt(0)) != 0 && (r.Cmp(big.NewInt(0)) == 0 || s.Cmp(big.NewInt(0)) == 0) {
		k = nbi().Rand(rand.New(rand.NewSource(time.Now().UnixNano())), nbi().Sub(kMax, big.NewInt(2)))
		k = k.Add(k, big.NewInt(1))

		// Allow injecting k
		if len(args) > 0 {
			if kVal, ok := args[0]["k"]; ok {
				k = kVal
			}
		}

		r = nbi().Mod(bigModExp(dk.g, k, dk.p), dk.q)
		s = nbi().Mod(nbi().Mul(nbi().ModInverse(k, dk.q), nbi().Add(h, nbi().Mul(dk.key, r))), dk.q)
	}

	return &DSASig{r, s}, nil
}

// Verify returns true if sig is a valid signature for message with key dk
func (dk *DSAKey) Verify(message []byte, sig *DSASig) (bool, error) {
	nbi := func() *big.Int { return new(big.Int) }

	if sig.r.Cmp(big.NewInt(0)) == 0 {
		return false, fmt.Errorf("bad signature: r == 0")
	}

	hBytes := sha1.Sum(message)
	h, success := nbi().SetString(hex.EncodeToString(hBytes[:]), 16)
	if !success {
		return false, fmt.Errorf("could not hash message")
	}

	w := nbi().ModInverse(sig.s, dk.q)
	u1 := nbi().Mod(nbi().Mul(h, w), dk.q)
	u2 := nbi().Mod(nbi().Mul(sig.r, w), dk.q)
	v := nbi().Mod(nbi().Mod(nbi().Mul(bigModExp(dk.g, u1, dk.p), bigModExp(dk.key, u2, dk.p)), dk.p), dk.q)

	return v.Cmp(sig.r) == 0, nil
}
