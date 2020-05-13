package cryptopals

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"math/rand"
	"testing"
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
