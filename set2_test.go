package cryptopals

import (
	"encoding/base64"
	"io/ioutil"
	"regexp"
	"strings"
	"testing"
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
