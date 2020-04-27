package cryptopals

import (
	"fmt"
	"math"
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
	if char >= 'a' && char <= 'z' {
		value = 1
	}

	if char >= 'A' && char <= 'Z' {
		value = 1
	}

	freqMap := map[byte]float64{
		' ': 10,
		'E': 12.02,
		'T': 9.1,
		'A': 8.12,
		'O': 7.68,
		'I': 7.31,
		'N': 6.95,
		'S': 6.28,
		'R': 6.02,
		'H': 5.92,
		'D': 4.32,
		'L': 3.98,
		'U': 2.88,
		'C': 2.71,
		'M': 2.61,
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
	for _, key := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz 0123456789" {
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
