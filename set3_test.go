package cryptopals

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func TestS3C17(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	data, err := ioutil.ReadFile("17.txt")
	assertNoError(t, err)

	randomStrings := make([][]byte, 10)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for i, line := range lines {
		randomString, err := base64.StdEncoding.DecodeString(line)
		assertNoError(t, err)
		randomStrings[i] = randomString
	}

	key := make([]byte, 16)
	_, err = rand.Read(key)
	assertNoError(t, err)

	encrypt := func() (cipherText []byte, iv []byte) {
		index := rand.Intn(10)
		fmt.Println("Sample", index)
		plainText := randomStrings[index]
		plainText, err = padPKCS7ToBlockSize(plainText, 16)
		assertNoError(t, err)

		iv = make([]byte, 16)
		_, err := rand.Read(iv)
		assertNoError(t, err)

		cipherText, err = encryptAESCBC(plainText, key, iv)
		assertNoError(t, err)

		return cipherText, iv
	}

	decrypt := func(cipherText []byte, iv []byte) bool {
		plainText, err := decryptAESCBC(cipherText, key, iv)
		assertNoError(t, err)

		plainText, err = unpadPKCS7(plainText)
		if err != nil {
			return false
		}

		fmt.Println(plainText, string(plainText))

		return true
	}

	crack := func(sample []byte, iv []byte) {
		crackedData := make([]byte, len(sample))
		buffer := make([]byte, len(sample))
		copy(buffer, sample)
		blockSize := 16
		for block := (len(sample) / blockSize) - 1; block >= 0; block-- {
			for byteIndex := blockSize - 1; byteIndex >= 0; byteIndex-- {
				i := (block * blockSize) + byteIndex
				prevI := ((block - 1) * blockSize) + byteIndex
				for j := 0; j < 256; j++ {
					buffer[prevI] = byte(j)
					if decrypt(buffer[block*blockSize:], buffer[(block-1)*blockSize:block*blockSize]) {
						crackedData[i] = 0x01 ^ byte(j) ^ sample[prevI]
						fmt.Println(i, prevI, j, crackedData[i], string(crackedData[i]))
					}
				}
				break
			}
			break
		}
	}

	sample, iv := encrypt()
	crack(sample, iv)
}
