package cryptopals

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestS2C9(t *testing.T) {
	plainText := "YELLOW SUBMARINE"
	want := "YELLOW SUBMARINE\x04\x04\x04\x04"

	paddedText, err := padPKCS7(plainText, 20)
	assertNoError(t, err)
	assertEquals(t, want, paddedText)
}

func TestS2C10(t *testing.T) {
	plainText := []byte("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE")
	key := []byte("1234567890ABCDEF")
	iv := make([]byte, 16)

	cipherText, err := encryptAESCBC(plainText, key, iv)
	assertNoError(t, err)

	newPlainText, err := decryptAESCBC(cipherText, key, iv)
	assertNoError(t, err)
	assertEquals(t, string(plainText), string(newPlainText))

	data, err := ioutil.ReadFile("10.txt")
	assertNoError(t, err)

	cipherText, err = base64.StdEncoding.DecodeString(string(data))
	plainText, err = decryptAESCBC(cipherText, []byte("YELLOW SUBMARINE"), iv)
	assertNoError(t, err)

	trimmedPlaintext := strings.Trim(string(plainText), "\x04\n ")
	re := regexp.MustCompile(`Play that funky music$`)
	assertEquals(t, true, re.MatchString(trimmedPlaintext))
}

func TestECBEncryptDecrypt(t *testing.T) {
	plainText := make([]byte, 16*100)
	_, err := rand.Read(plainText)
	assertNoError(t, err)
	key := make([]byte, 16)
	_, err = rand.Read(key)
	assertNoError(t, err)

	cipherText, err := encryptAESECB(plainText, key, 16)
	assertNoError(t, err)

	newPlainText, err := decryptAESECB(cipherText, key, 16)
	assertNoError(t, err)

	assertEquals(t, true, bytes.Equal(plainText, newPlainText))
}

func TestS2C11(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	plainText, err := ioutil.ReadFile("S2C11.txt")
	assertNoError(t, err)

	cipherText, err := encryptAESRandom(plainText)
	assertNoError(t, err)

	similarity, err := numSimilarBlocks(cipherText, 16, 0)
	assertNoError(t, err)

	// If there are any similar blo
	if similarity > 0 {
		fmt.Println(similarity, "ECB")
	} else {
		fmt.Println(similarity, "CBC")
	}
}
