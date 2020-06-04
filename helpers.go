package cryptopals

import (
	"fmt"
	"math"
	"strconv"
)

// hamming returns the edit/hamming distance betwen a and b. The hamming
// distance is defined by the number of bits that are different between two
// values.
func hamming(a []byte, b []byte) (int, error) {
	if len(a) != len(b) {
		return -1, fmt.Errorf("strings not equal length")
	}

	length := len(a)
	if length == 0 {
		return 0, nil
	}

	// The technique: XOR the two values and count the number of 1-bits
	// in the result.
	count := 0
	for i := range a {
		// XOR the bytes, the number of remaining 1-bits represent
		// the differing bits.
		diff := a[i] ^ b[i]

		// Count the number of 1-bits in the result
		for j := 0; j < 8; j++ {
			count += int(diff & 1)
			diff >>= 1
		}
	}

	return count, nil
}

// Decrypt cipherText (encrypted with repeating-key-XOR) using
func decryptRepeatingKeyXOR(cipherText []byte, key []byte) []byte {
	plainText := make([]byte, len(cipherText))
	for i := 0; i < len(cipherText); i += len(key) {
		end := i + len(key)
		if end > len(cipherText) {
			end = len(cipherText)
		}

		for j := range key {
			if i+j < end {
				plainText[i+j] = cipherText[i+j] ^ key[j]
			}
		}
	}

	return plainText
}

// This function returns the mean hamming distance between blocks of size
// blockSize.
func meanBlockHammingDistance(data []byte, blockSize int, opts ...map[string]string) (float64, error) {
	// Get the average of maxBlocks blocks
	maxBlocks := 10

	if len(opts) > 0 {
		intBlocks, err := strconv.ParseInt(opts[0]["maxBlocks"], 10, 16)
		maxBlocks = int(intBlocks)
		if err != nil {
			return 0, fmt.Errorf("could not parse opts: %w", err)
		}
	}

	meanDistance := float64(0)
	for i := 0; i < maxBlocks; i++ {
		start := i * blockSize
		first := data[start : start+blockSize]
		second := data[start+blockSize : start+blockSize+blockSize]
		distance, err := hamming(first, second)

		if err != nil {
			return 0, fmt.Errorf("could not compute hamming distance: %w", err)
		}

		normalizedDistance := float64(distance) / float64(blockSize)
		meanDistance += normalizedDistance
		meanDistance /= 2
	}

	return meanDistance, nil
}

// Returns the total hamming distance between each block and every other
// block in data, given blockSize.
func blockDistance(data []byte, blockSize int) (float64, error) {
	numBlocks := len(data) / blockSize

	totalDistance := float64(0)
	for i := 0; i < numBlocks; i++ {
		for j := i; j < numBlocks; j++ {
			if i == j {
				continue
			}
			first := data[i*blockSize : (i+1)*blockSize]
			second := data[j*blockSize : (j+1)*blockSize]
			distance, err := hamming(first, second)
			if err != nil {
				return 0, fmt.Errorf("could not compute hamming distance: %w", err)
			}

			totalDistance += math.Pow(float64(distance)/float64(blockSize), 2)
		}
	}

	return math.Sqrt(totalDistance), nil
}

// Returns the number of blocks that have a similarity score under minSimilarity. The score
// is the hamming distance between the blocks.
func numSimilarBlocks(data []byte, blockSize int, minSimilarity int) (int, error) {
	numBlocks := len(data) / blockSize

	count := 0
	for i := 0; i < numBlocks; i++ {
		for j := i; j < numBlocks; j++ {
			if i == j {
				continue
			}
			first := data[i*blockSize : (i+1)*blockSize]
			second := data[j*blockSize : (j+1)*blockSize]
			distance, err := hamming(first, second)
			if err != nil {
				return 0, fmt.Errorf("could not compute hamming distance: %w", err)
			}

			if distance <= minSimilarity {
				count++
			}
		}
	}

	return count, nil
}

// Zero-pad hex strings to even-valued length. This is useful because big.Int returns hex values that
// are odd-length, and break some hex parsers.
func zeroPad(s string) string {
	if len(s)%2 == 1 {
		return "0" + s
	}
	return s
}

// Zero-pad bytes to even-valued length. This works exactly like zeroPad does, except on strings.
func zeroPadBytes(s []byte) []byte {
	if len(s)%2 == 1 {
		return append([]byte{0}, s...)
	}
	return s
}
