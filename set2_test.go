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

	detectedBlockSize, err := detectBlockSize(cipherText)
	assertNoError(t, err)

	// If there are any similar blocks, then this is ECB
	if similarity > 0 {
		fmt.Println(similarity, "ECB", detectedBlockSize)
	} else {
		fmt.Println(similarity, "CBC", detectedBlockSize)
	}
}

func TestS2C12(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	key := make([]byte, 16)
	_, err := rand.Read(key)
	assertNoError(t, err)

	secretData, err := ioutil.ReadFile("12.txt")
	assertNoError(t, err)

	secret, err := base64.StdEncoding.DecodeString(string(secretData))
	assertNoError(t, err)

	encrypt := func(plainText []byte) ([]byte, error) {
		newPlainText := append(plainText, secret...)
		newPlainText, err = padPKCS7ToBlockSize(newPlainText, 16)
		if err != nil {
			return nil, fmt.Errorf("could not PKCS7 pad: %w", err)
		}

		cipherText, err := encryptAESECB(newPlainText, key, 16)
		if err != nil {
			return nil, fmt.Errorf("could not ECB encrypt: %w", err)
		}

		return cipherText, nil
	}

	isECB, blockSize, err := detectAESECB(encrypt)
	assertNoError(t, err)
	assertEquals(t, true, isECB)
	assertEquals(t, 16, blockSize)

	// Crack ECB byte-at-a-time
	crackedSecret := []byte{}
	crack := func(blockSize, maxLen int) bool {
		if len(crackedSecret) > maxLen {
			return false
		}

		// Allocate enough room to crack up to maxLen bytes
		prefixLen := maxLen - (len(crackedSecret) % maxLen) - 1
		prefix := make([]byte, prefixLen, maxLen)
		for i := 0; i < len(prefix); i++ {
			prefix[i] = 'A'
		}

		// Encrypt data prefixed by 1-fewer byte than needed
		cipherPrefix, err := encrypt(prefix)
		assertNoError(t, err)

		// Append what we've cracked so far
		prefix = append(prefix, crackedSecret...)

		// Lengthen prefix to make it maxLen bytes
		prefix = append(prefix, '0')
		for testByte := byte(0); testByte < 255; testByte++ {
			prefix[maxLen-1] = testByte
			cipherText, err := encrypt(prefix)
			assertNoError(t, err)

			if bytes.Equal(cipherPrefix[:maxLen], cipherText[:maxLen]) {
				crackedSecret = append(crackedSecret, testByte)
				return true
			}
		}

		return false
	}

	// Figure out length of secret
	cipherText, err := encrypt([]byte{})
	assertNoError(t, err)

	// Start crackin'
	for crack(blockSize, len(cipherText)) {
	}

	fmt.Println(string(crackedSecret))
	assertEquals(t, bytes.Equal(secret, crackedSecret[:len(secret)]), true)
}
