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
	value := float64(0)
	if char >= 'a' && char <= 'z' {
		value = 0.3
	}

	if char >= 'A' && char <= 'Z' {
		value = 0.3
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

// Calculates the liklihood of str being an English string
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

	freqMap := map[byte]float64{}
	for k, v := range countMap {
		freqMap[k] = float64(v) / float64(totalChars)
	}

	cost := float64(0)
	for _, char := range str {
		c := strings.ToUpper(string(char))[0]
		expectedFreq := getExpectedFreqForChar(c) / (float64(100))
		observedFreq := freqMap[c]

		cost += math.Pow(expectedFreq-observedFreq, 2)
		fmt.Printf("char: %s, expected: %v, observed: %v, cost: %v\n", string(c), expectedFreq, observedFreq, cost)
	}

	return cost
}

// Calculates the liklihood of str being an English string
func calcStringScore(str []byte) float64 {
	score := float64(0)
	for _, char := range str {
		c := strings.ToUpper(string(char))[0]
		score += getExpectedFreqForChar(c)
	}

	return score
}

func crackXORByte(cipherText []byte) (key byte, cost float64, plainText string) {
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

func crackXORByte2(cipherText []byte) (key byte, cost float64, plainText string) {
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
