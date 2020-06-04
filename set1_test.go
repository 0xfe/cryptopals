package cryptopals

/*
## Cryptopals Solutions by Mohit Muthanna Cheppudira 2020.

This file consists of solutions to Set 1. Run with:

  $ go test -v --run S1
*/

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The first few challenges are really straightforward, and mostly mechanical.
func TestS1C1(t *testing.T) {
	inHex := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	wantBase64 := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	bytes, err := hex.DecodeString(inHex)
	assertNoError(t, err)
	gotBase64 := base64.StdEncoding.EncodeToString(bytes)

	assertEquals(t, wantBase64, gotBase64)
}

func TestS1C2(t *testing.T) {
	inHex1 := "1c0111001f010100061a024b53535009181c"
	inHex2 := "686974207468652062756c6c277320657965"
	wantHex := "746865206b696420646f6e277420706c6179"

	bytes1, err := hex.DecodeString(inHex1)
	assertNoError(t, err)
	bytes2, err := hex.DecodeString(inHex2)
	assertNoError(t, err)

	// Barebones byte-at-a-time XOR decryption
	out := make([]byte, len(bytes1))
	for i := range bytes1 {
		out[i] = bytes1[i] ^ bytes2[i]
	}

	gotHex := hex.EncodeToString(out)
	assertEquals(t, wantHex, gotHex)
}

// This method extracts the byte-at-a-time XOR decryption from the previous challenge.
func decryptXORByte(data []byte, key byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key
	}

	return out
}

// Try to crack cipherText by XOR-decrypting using all 255 characters as the key, then
// using a letter-frequency analysis to weed out the english text.
func crackXORByteCost(cipherText []byte) (key byte, cost float64, plainText string) {
	bestCost := float64(len(cipherText) * 100)
	var bestString string
	var bestKey byte
	for i := 0; i < 256; i++ {
		key := byte(i)
		plainText := decryptXORByte(cipherText, byte(key))

		// Calculate the "englishness" of plainText. Lower is better.
		cost := math.Sqrt(calcStringCost(plainText))

		// Keep track of the lowest cost.
		if cost < bestCost {
			bestCost = cost
			bestString = string(plainText)
			bestKey = byte(key)
		}
	}

	return bestKey, bestCost, bestString
}

func TestS1C3(t *testing.T) {
	cipherTextHex := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	cipherText, err := hex.DecodeString(cipherTextHex)
	assertNoError(t, err)

	bestKey, bestCost, bestString := crackXORByteCost(cipherText)

	fmt.Println(bestKey, bestCost, bestString)
	assertEquals(t, bestKey, byte(88))
	assertEquals(t, bestString, "Cooking MC's like a pound of bacon")
}

func TestS1C4(t *testing.T) {
	data, err := ioutil.ReadFile("data/4.txt")
	assertNoError(t, err)
	lines := strings.Split(string(data), "\n")

	bestCost := float64(1000)
	bestPlainText := ""
	for _, line := range lines {
		cipherText, err := hex.DecodeString(line)
		assertNoError(t, err)

		_, cost, plainText := crackXORByteCost(cipherText)
		if cost < bestCost {
			bestPlainText = plainText
			bestCost = cost
		}
	}

	fmt.Println(bestCost, bestPlainText)
	assertEquals(t, "Now that the party is jumping\n", bestPlainText)
}

func TestS1C5(t *testing.T) {
	plainText := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key := "ICE"
	want := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	// XOR encrypt plainText using a multi-byte key.
	cipherText := make([]byte, len(plainText))
	for i := 0; i < len(plainText); i += len(key) {
		end := i + len(key)
		if end > len(plainText) {
			end = len(plainText)
		}

		for j := range key {
			if i+j < end {
				cipherText[i+j] = plainText[i+j] ^ key[j]
			}
		}
	}

	assertEquals(t, want, hex.EncodeToString(cipherText))
}

func TestHammingDistance(t *testing.T) {
	distance, err := hamming([]byte("this is a test"), []byte("wokka wokka!!!"))
	assertNoError(t, err)
	assertEquals(t, 37, distance)
}

// DistanceMap is a helper struct for sorting by hamming distance, used by the next challenge.
type DistanceMap struct {
	keySize  int
	distance float64
}

type DistanceList []DistanceMap

func (d DistanceList) Len() int           { return len(d) }
func (d DistanceList) Swap(i, j int)      { (d)[i], (d)[j] = (d)[j], (d)[i] }
func (d DistanceList) Less(i, j int) bool { return d[i].distance < d[j].distance }

func TestS1C6(t *testing.T) {
	data, err := ioutil.ReadFile("data/6.txt")
	assertNoError(t, err)

	cipherText, err := base64.StdEncoding.DecodeString(string(data))
	assertNoError(t, err)

	// Calculate the mean block hamming distance for all key sizes between 2 and 40. This
	// helps us determine the block size of the cipher text.
	distances := DistanceList{}
	for keySize := 2; keySize <= 40; keySize++ {
		meanDistance, err := meanBlockHammingDistance(cipherText, keySize)
		assertNoError(t, err)

		distances = append(distances, DistanceMap{
			keySize:  keySize,
			distance: meanDistance,
		})
	}

	// Sort to get lowest edit-distance key sizes
	sort.Sort(distances)

	bestCost := float64(100000000)
	bestPlainText := ""
	bestKey := ""
	// We'll test the top three key/block sizes.
	for i := 0; i < 3; i++ {
		keySize := distances[i].keySize

		// Create keySize buckets (km) -- each bucket represents N%keysize'th
		// character of the ciphertext
		km := make([][]byte, keySize)
		for j := range km {
			km[j] = make([]byte, (len(cipherText)/keySize)+1)
		}

		for j := range cipherText {
			bucket := j % keySize
			loc := j / keySize
			km[bucket][loc] = byte(cipherText[j])
		}

		keys := []byte{}
		totalCost := float64(0)
		for j := range km {
			block := km[j]
			key, cost, _ := crackXORByteCost(block)
			keys = append(keys, key)
			totalCost += cost
		}

		if totalCost < bestCost {
			bestKey = string(keys)
			bestPlainText = string(decryptRepeatingKeyXOR(cipherText, keys))
			bestCost = totalCost
		}
		fmt.Printf("cost: %f, key: %s\n", totalCost, string(keys))
	}

	fmt.Printf("Best plaintext length: %d\n", len(bestPlainText))
	fmt.Printf("Best key: %s, Best cost: %f\n", bestKey, bestCost)
	assertEquals(t, "Terminator X: Bring the noise", bestKey)
}

func TestS1C7(t *testing.T) {
	key := "YELLOW SUBMARINE"
	data, err := ioutil.ReadFile("data/7.txt")
	assertNoError(t, err)

	cipherText, err := base64.StdEncoding.DecodeString(string(data))
	assertNoError(t, err)

	plainText, err := decryptAESECB(cipherText, []byte(key), 16)
	assertNoError(t, err)

	fmt.Println(string(plainText))
	trimmedPlaintext := strings.Trim(string(plainText), "\x04\n ")
	re := regexp.MustCompile(`Play that funky music$`)
	assertEquals(t, true, re.MatchString(trimmedPlaintext))
}

func TestS1C8(t *testing.T) {
	data, err := ioutil.ReadFile("data/8.txt")
	assertNoError(t, err)

	blockSize := 16
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	bestCount := 0
	bestLine := -1
	for i, line := range lines {
		cipherText, err := hex.DecodeString(line)
		assertNoError(t, err)
		count, err := numSimilarBlocks(cipherText, blockSize, 0)
		assertNoError(t, err)

		if count > bestCount {
			bestCount = count
			bestLine = i
		}
	}

	assertEquals(t, 132, bestLine)
	assertEquals(t, 6, bestCount)

	fmt.Printf("ECB encrypted line: %d, num similar blocks: %d, content: %s\n", bestLine+1, bestCount, lines[bestLine])
}
