package cryptopals

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand"
	"regexp"
	"testing"
	"time"
)

func TestS4C25(t *testing.T) {
	// Load encrypted data, decrypt with EBC (using key from C10), and
	// reencrypt with CTR.
	data, err := ioutil.ReadFile("25.txt")
	assertNoError(t, err)

	cipherText, err := base64.StdEncoding.DecodeString(string(data))
	assertNoError(t, err)

	plainText, err := decryptAESECB(cipherText, []byte("YELLOW SUBMARINE"), 16)
	assertNoError(t, err)

	plainText, err = unpadPKCS7(plainText)
	assertNoError(t, err)

	nonce := uint64(rand.Int63())
	key := make([]byte, 16)
	_, err = rand.Read(key)
	assertNoError(t, err)
	cipherText, err = encryptAESCTR(plainText, key, nonce)
	assertNoError(t, err)

	// This function allows you to edit a slice of the cipherText, returns new
	// cipherText
	edit := func(cipherText []byte, key []byte, offset int, newText []byte) []byte {
		plainText, err := decryptAESCTR(cipherText, key, nonce)
		assertNoError(t, err)
		copy(plainText[offset:offset+len(newText)], newText)
		newCipherText, err := encryptAESCTR(plainText, key, nonce)
		assertNoError(t, err)
		return newCipherText
	}

	// Try a chosen-plaintext attack to determine the keystream
	attackText := bytes.Repeat([]byte{'A'}, len(cipherText))
	newCipherText := edit(cipherText, key, 0, attackText)

	keyStream := make([]byte, len(newCipherText))
	for i, v := range newCipherText {
		keyStream[i] = v ^ 'A'
	}

	newPlainText := make([]byte, len(cipherText))
	for i, v := range cipherText {
		newPlainText[i] = v ^ keyStream[i]
	}

	assertTrue(t, bytes.Equal(plainText, newPlainText))
}

func TestS4C26(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	key := make([]byte, 16)
	_, err := rand.Read(key)
	assertNoError(t, err)
	nonce := uint64(rand.Int63())
	pre := []byte("comment1=cooking%20MCs;userdata=")
	post := []byte(";comment2=%20like%20a%20pound%20of%20bacon")

	encrypt := func(input []byte) ([]byte, error) {
		sanitizedInput := []byte{}
		for _, c := range input {
			if c != ';' && c != '=' {
				sanitizedInput = append(sanitizedInput, c)
			}
		}

		plainText := append(pre, append(sanitizedInput, post...)...)

		cipherText, err := encryptAESCTR(plainText, key, nonce)
		if err != nil {
			return nil, fmt.Errorf("could not CTR encrypt: %w", err)
		}

		return cipherText, nil
	}

	decrypt := func(cipherText []byte) ([]byte, error) {
		plainText, err := decryptAESCTR(cipherText, key, nonce)
		if err != nil {
			return nil, fmt.Errorf("could not CBC decrypt: %w", err)
		}

		return plainText, nil
	}

	isCracked := func(cipherText []byte) bool {
		plainText, err := decrypt(cipherText)
		assertNoError(t, err)

		match, err := regexp.MatchString(";admin=true;", string(plainText))
		assertNoError(t, err)

		return match
	}

	cipherText, err := encrypt([]byte(";admin=true;"))
	assertNoError(t, err)
	assertFalse(t, isCracked(cipherText))

	// Flips a single bit in data, indexed by byteIndex and bitIndex
	flipBit := func(data []byte, byteIndex int, bitIndex int) {
		data[byteIndex] ^= byte((1 << 7) >> bitIndex)
	}

	adminBlock := []byte(";admin=true;")
	flipBit(adminBlock, 0, 7)
	flipBit(adminBlock, 6, 7)
	flipBit(adminBlock, 11, 7)

	attackBlock := append(pre, append(adminBlock, post...)...)
	cipherText, err = encrypt(adminBlock)
	assertEquals(t, len(attackBlock), len(cipherText))

	flipBit(cipherText, 32, 7)
	flipBit(cipherText, 32+6, 7)
	flipBit(cipherText, 32+11, 7)
	assertTrue(t, isCracked(cipherText))
}
