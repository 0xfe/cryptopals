package cryptopals

/*
## Cryptopals Solutions by Mohit Muthanna Cheppudira 2020.

This file consists of text analysis functions to detect the validity of
plain-text blocks.
*/

import (
	"math"
	"strings"
)

// getExpectedFreqForChar returns the probabilty of char being in a piece
// of english text. This is not a complete set -- I pulled the numbers from
// some website \o/
func getExpectedFreqForChar(char byte) float64 {
	// Default value (helps prevent divide-by-zero)
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
