package cryptopals

import (
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"testing"
	"time"
)

func bigModExp(base *big.Int, exponent *big.Int, modulus *big.Int) *big.Int {
	if modulus.Cmp(big.NewInt(1)) == 0 {
		return big.NewInt(0)
	}

	if exponent.Cmp(big.NewInt(0)) == 0 {
		return big.NewInt(1)
	}

	result := bigModExp(base, new(big.Int).Div(exponent, big.NewInt(2)), modulus)
	result = new(big.Int).Mod(new(big.Int).Mul(result, result), modulus)

	// if exponent & 1 != 0, means, if exponent % 2 != 0, means, if exponent is not divisible by 2
	if new(big.Int).Mod(exponent, big.NewInt(2)).Int64() != 0 {
		return new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Mod(base, modulus), result), modulus)
	}

	return new(big.Int).Mod(result, modulus)
}

func TestS5C33(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	p := uint64(37)
	g := uint64(5)

	a := uint64(rand.Intn(10)) % p
	A := uint64(math.Pow(float64(g), float64(a))) % p

	b := uint64(rand.Intn(10)) % p
	B := uint64(math.Pow(float64(g), float64(b))) % p

	s1 := uint64(math.Pow(float64(B), float64(a))) % p
	s2 := uint64(math.Pow(float64(A), float64(b))) % p

	fmt.Printf("a = %d, b = %d, p = %d, g = %d\n", a, b, p, g)
	fmt.Printf("verifying s1 (%d) == s2 (%d)\n", s1, s2)

	assertEquals(t, s1, s2)

	modExp := func(base *big.Int, exponent *big.Int, modulus *big.Int) *big.Int {
		return new(big.Int).Mod(new(big.Int).Exp(base, exponent, nil), modulus)
	}

	// Validate that modExp works with small numbers
	fmt.Printf("verifying (g ^ a) %% p = A\n")
	fmt.Printf("i.e., (%d ^ %d) %% %d = %d\n", g, a, p, A)
	assertEquals(t, int64(A), modExp(big.NewInt(int64(g)), big.NewInt(int64(a)), big.NewInt(int64(p))).Int64())
	assertEquals(t, int64(A), bigModExp(big.NewInt(int64(g)), big.NewInt(int64(a)), big.NewInt(int64(p))).Int64())

	// Do the same thing with BigNums
	bpStr := "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
	bpBytes, err := hex.DecodeString(bpStr)
	assertNoError(t, err)

	bp := new(big.Int).SetBytes(bpBytes)
	bg := big.NewInt(2)

	ba := new(big.Int).Mod(big.NewInt(rand.Int63()), bp)
	bA := bigModExp(bg, ba, bp)

	bb := new(big.Int).Mod(big.NewInt(rand.Int63()), bp)
	bB := bigModExp(bg, bb, bp)

	bs1 := bigModExp(bB, ba, bp)
	bs2 := bigModExp(bA, bb, bp)

	fmt.Println("verifying s1 == s2 with big nums")
	assertTrue(t, bs1.Cmp(bs2) == 0)
}
