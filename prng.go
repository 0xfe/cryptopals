package cryptopals

/*
## Cryptopals Solutions by Mohit Muthanna Cheppudira 2020.

Implementation of Mersenne Twister from: https://en.wikipedia.org/wiki/Mersenne_Twister
*/

import (
	"fmt"
	"math"
)

// Twister represents the internal state for a Mersenne Twister. This is setup for 32-bit
// word sizes. To make this work for 64-bit (and 32-bit), change uint32s to uint64s, and
// return lowest-W bits where necessary (see wikipidea pseudocode).
type Twister struct {
	// Configuration
	w int    // word size (number of bits)
	n int    // degree of recurrence
	m int    // middle word, an offset used in the recurrence relation defining the series x, 1 ≤ m < n
	r uint32 // separation point of one word, or the number of bits of the lower bitmask, 0 ≤ r ≤ w - 1
	a uint32 // coefficients of the rational normal form twist matrix

	// GFSR(R) tempering bit shifts
	s uint32
	t uint32

	// TGFSR(R) tempering bitmasks
	b uint32
	c uint32

	// additional Mersenne Twister tempering bit shifts/masks
	u uint32
	d uint32
	l uint32

	// another parameter to the generator, though not part of the algorithm proper
	f uint32

	// Internal state
	MT        []uint32
	index     int
	lowerMask uint32
	upperMask uint32
}

// NewMT19937Twister returns a new Mersenne Twister instance
func NewMT19937Twister() *Twister {
	n := 624
	w := 32

	// Internal state
	index := n
	MT := make([]uint32, n)
	lowerMask := uint32((1 << int(w)) - 1)
	upperMask := ^lowerMask

	twister := &Twister{
		w: w,
		n: n,
		m: 397,
		r: 31,

		a: 0x9908B0DF,

		u: 11,
		d: 0xFFFFFFFF,

		s: 7,
		b: 0x9D2C5680,

		t: 15,
		c: 0xEFC60000,
		l: 18,
		f: 1812433253,

		MT:        MT,
		index:     index,
		lowerMask: lowerMask,
		upperMask: upperMask,
	}

	twister.Seed(5489)
	return twister
}

// Handy for debugging the internal state
func (t *Twister) String() string {
	return fmt.Sprintf("w: %d, n: %d, index: %d, MT(%d): %+v...", t.w, t.n, t.index, len(t.MT), t.MT[:5])
}

// Seed seeds the PRNG
func (t *Twister) Seed(seed uint32) {
	t.MT[0] = seed
	for i := 1; i < t.n; i++ {
		t.MT[i] = (t.f*(t.MT[i-1]^(t.MT[i-1]>>(t.w-2))) + uint32(i))
	}
}

// SetMT sets a custom internal state for PRNG
func (t *Twister) SetMT(mt []uint32) {
	t.MT = mt
}

// Temper diffuses the bits in "y"
func (t *Twister) temper(y uint32) uint32 {
	y ^= (y >> t.u) & t.d // op1
	y ^= (y << t.s) & t.b // op2
	y ^= (y << t.t) & t.c // op3
	y ^= y >> t.l         // op4
	return y
}

// Untemper reconstructs "y" from diffused/tempered value. This is part of
// a Cryptopals challenge solution.
func (t *Twister) untemper(y uint32) uint32 {
	y ^= y >> t.l         // reverse op4
	y ^= (y << t.t) & t.c // reverse op3

	// reverse op2
	shiftMask := uint32(math.Pow(2, 7) - 1)
	for i := 0; i < 4; i++ {
		b := t.b & uint32(shiftMask<<uint32(t.s*(uint32(i)+1)))
		y ^= ((y << t.s) & b)
	}

	// reverse op1
	for i := 0; i < 3; i++ {
		y ^= (y >> t.u)
	}

	return y
}

// Read returns a random int32
func (t *Twister) Read() uint32 {
	if t.index == t.n {
		t.Twist()
	}

	// Tap a value from the internal state matrix, and "temper" it. Tempering
	// diffuses the value across the bit space.
	y := t.temper(t.MT[t.index])
	t.index++
	return y
}

// Twist generates the next N values for MT
func (t *Twister) Twist() {
	for i := 0; i < t.n; i++ {
		x := (t.MT[i] & t.upperMask) + (t.MT[(i+1)%t.n] & t.lowerMask)
		xA := x >> 1
		if x%2 != 0 {
			xA ^= t.a
		}

		t.MT[i] = t.MT[(i+t.m)%t.n] ^ xA
	}

	t.index = 0
}
