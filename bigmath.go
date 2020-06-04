package cryptopals

/*
## Cryptopals Solutions by Mohit Muthanna Cheppudira 2020.

This file consists of helper methods for modular arithmetic with big integers.
*/

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os/exec"
)

// Modular exponentiation for big.Int. Calculates (base^exponent) mod modulus using
// a varient of Euclid's algorithm.
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

// Cube-root for big.Int. Returns the cube root of i, and a remainder.
func bigCubeRt(i *big.Int) (cbrt *big.Int, rem *big.Int) {
	var (
		n0    = big.NewInt(0)
		n1    = big.NewInt(1)
		n2    = big.NewInt(2)
		n3    = big.NewInt(3)
		guess = new(big.Int).Div(i, n2)
		dx    = new(big.Int)
		absDx = new(big.Int)
		minDx = new(big.Int).Abs(i)
		step  = new(big.Int).Abs(new(big.Int).Div(guess, n2))
		cube  = new(big.Int)
	)

	for {
		cube.Exp(guess, n3, nil)
		dx.Sub(i, cube)
		cmp := dx.Cmp(n0)
		if cmp == 0 {
			return guess, n0
		}

		absDx.Abs(dx)
		switch absDx.Cmp(minDx) {
		case -1:
			minDx.Set(absDx)
		case 0:
			return guess, dx
		}

		switch cmp {
		case -1:
			guess.Sub(guess, step)
		case +1:
			guess.Add(guess, step)
		}

		step.Div(step, n2)
		if step.Cmp(n0) == 0 {
			step.Set(n1)
		}
	}
}

// generatePrime generates a huuuuuuge prime number using OpenSSL
func generatePrime(numBits int) *big.Int {
	// Instead of finding large primes ourselves, we'll use OpenSSL. Start with 1024-bit
	// primes, which gives us 2048-bit RSA keys.
	fmt.Printf("$ openssl prime -generate -bits %d -hex\n", numBits)
	pOut, _ := exec.Command("openssl", "prime", "-generate", "-bits", fmt.Sprintf("%d", numBits), "-hex").Output()
	pBytes, _ := hex.DecodeString(string(pOut))

	return new(big.Int).SetBytes(pBytes)
}

// generatePrimeNative generates a huuuuuuuuuge prime number using crypto/rand
func generatePrimeNative(numBits int) *big.Int {
	v, err := rand.Prime(rand.Reader, numBits)
	if err != nil {
		panic("could not generate prime number")
	}

	fmt.Println("Generated prime:", v.Text(16))

	return v
}

// Returns ceiling of x / y
func bigCeilDiv(x, y *big.Int) *big.Int {
	ceil := new(big.Int)
	return ceil.Add(x, y).Sub(ceil, big.NewInt(1)).Div(ceil, y)
}

// Returns floor of x / y
func bigFloorDiv(x, y *big.Int) *big.Int {
	return new(big.Int).Div(x, y)
}

// Returns max of x and y
func bigMax(x, y *big.Int) *big.Int {
	if x.Cmp(y) < 0 {
		return y
	}

	return x
}

// Returns min of x and y
func bigMin(x, y *big.Int) *big.Int {
	if x.Cmp(y) < 0 {
		return x
	}

	return y
}
