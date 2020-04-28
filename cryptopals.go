package cryptopals

import (
	"crypto/aes"
	"fmt"
	"math"
	"strconv"
	"strings"
)

func decryptXORByte(data []byte, key byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key
	}

	return out
}

func getExpectedFreqForChar(char byte) float64 {
	value := float64(0.00001)

	freqMap := map[byte]float64{
		' ':  10,
		'\'': 0.1,
		'\n': 0.1,
		',':  0.1,
		'.':  0.1,
		'E':  12.02,
		'T':  9.1,
		'A':  8.12,
		'O':  7.68,
		'I':  7.31,
		'N':  6.95,
		'S':  6.28,
		'R':  6.02,
		'H':  5.92,
		'D':  4.32,
		'L':  3.98,
		'U':  2.88,
		'C':  2.71,
		'M':  2.61,
		'F':  2.3,
		'Y':  2.11,
		'W':  2.09,
		'G':  2.03,
		'P':  1.82,
		'B':  1.49,
		'V':  1.11,
		'K':  0.69,
		'X':  0.17,
		'Q':  0.11,
		'J':  0.10,
		'Z':  0.1,
		'0':  0.1,
		'1':  0.2,
		'2':  0.1,
		'3':  0.1,
		'4':  0.1,
		'5':  0.1,
		'6':  0.1,
		'7':  0.1,
		'8':  0.1,
		'9':  0.1,
	}

	if freq, ok := freqMap[strings.ToUpper(string(char))[0]]; ok {
		value = freq
	}

	return value
}

// Calculates the liklihood of str being an English string using chi-squared testing. Lower
// cost means higher liklihood.
func calcStringCost(str []byte) float64 {
	countMap := map[byte]int{}
	totalChars := len(str)

	for _, char := range str {
		key := strings.ToUpper(string(char))[0]
		if count, ok := countMap[key]; ok {
			countMap[key] = count + 1
		} else {
			countMap[key] = 1
		}
	}

	cost := float64(0)
	for k, v := range countMap {
		expectedCount := (getExpectedFreqForChar(k) / 100) * float64(totalChars)
		observedCount := float64(v)

		cost += math.Pow(expectedCount-observedCount, 2) / expectedCount
	}

	return cost
}

// Calculates the liklihood of str being an English string using correlation. Higher score
// means higher liklihood.
func calcStringScore(str []byte) float64 {
	score := float64(0)
	for _, char := range str {
		c := strings.ToUpper(string(char))[0]
		score += getExpectedFreqForChar(c)
	}

	return score
}

func crackXORByteCost(cipherText []byte) (key byte, cost float64, plainText string) {
	bestCost := float64(len(cipherText) * 100)
	var bestString string
	var bestKey byte
	for _, key := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz 0123456789.,';+=!?/\":<>\\|][{}_`~@#$%^&*()" {
		plainText := decryptXORByte(cipherText, byte(key))
		cost := math.Sqrt(calcStringCost(plainText))

		if cost < bestCost {
			bestCost = cost
			bestString = string(plainText)
			bestKey = byte(key)
		}
	}

	return bestKey, bestCost, bestString
}

func crackXORByteScore(cipherText []byte) (key byte, cost float64, plainText string) {
	bestScore := float64(0)
	var bestString string
	var bestKey byte
	for _, key := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz 0123456789" {
		plainText := decryptXORByte(cipherText, byte(key))
		score := calcStringScore(plainText)

		if score > bestScore {
			bestScore = score
			bestString = string(plainText)
			bestKey = byte(key)
		}
	}

	return bestKey, bestScore, bestString
}

func hamming(a []byte, b []byte) (int, error) {
	if len(a) != len(b) {
		return -1, fmt.Errorf("strings not equal length")
	}

	length := len(a)
	if length == 0 {
		return 0, nil
	}

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

// Returns the number of blocks that have a similarity score under minSimilarity. The score
// is the hamming distance between the blocks.
func numSimilarBlocks(data []byte, blockSize int, minSimilarity int) (int, error) {
	numBlocks := len(data) / blockSize

	count := 0
	for i := 0; i < numBlocks; i++ {
		for j := 0; j < numBlocks; j++ {
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

func decryptAESECB(cipherText []byte, key []byte, blockSize int) ([]byte, error) {
	plainText := make([]byte, len(cipherText))
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("could not initialize AES: %w", err)
	}

	for i := 0; i < (len(plainText) / blockSize); i++ {
		start := i * blockSize
		end := (i + 1) * blockSize
		cipher.Decrypt(plainText[start:end], cipherText[start:end])
	}

	return plainText, nil
}
