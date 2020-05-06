package cryptopals

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func TestS3C17(t *testing.T) {
	blockSize := 16
	rand.Seed(time.Now().UnixNano())

	// Read random strings from file
	data, err := ioutil.ReadFile("17.txt")
	assertNoError(t, err)

	randomStrings := make([][]byte, 10)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for i, line := range lines {
		randomString, err := base64.StdEncoding.DecodeString(line)
		assertNoError(t, err)
		randomStrings[i] = randomString
	}

	// Create a new AES key for this challenge
	key := make([]byte, 16)
	_, err = rand.Read(key)
	assertNoError(t, err)

	// Encrypt one of the strings at random using the above key, and return cipherText + iv
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

	// Decrypt cipherText, attempt to unpad and return false if padding is invalid.
	decrypt := func(cipherText []byte, iv []byte) bool {
		plainText, err := decryptAESCBC(cipherText, key, iv)
		assertNoError(t, err)

		plainText, err = unpadPKCS7(plainText)
		if err != nil {
			return false
		}

		return true
	}

	// Attempt to decrypt one block using a CBC padding oracle attack. This
	// relies on the leak from PKCS7 padding errors.
	//
	// Turns out you only need the previous block to crack a block. A CBC
	// block is a function of a key and the previous block.
	crack := func(block []byte, prevBlock []byte) []byte {
		// We're going to mutate the previous block, so make a copy
		prevBuffer := make([]byte, len(block))
		copy(prevBuffer, prevBlock)

		crackedData := make([]byte, len(block))
		for i := blockSize - 1; i >= 0; i-- {
			paddingByte := byte(blockSize - i)
			for j := 0; j < 256; j++ {
				prevBuffer[i] = byte(j)
				if decrypt(block, prevBuffer) {
					crackedByte := paddingByte ^ byte(j) ^ prevBlock[i]
					if byte(j) != prevBlock[i] || paddingByte != 1 {
						crackedData[i] = crackedByte

						// Update previous buffer for next padding byte
						if paddingByte < byte(blockSize) {
							for k := i; k < blockSize; k++ {
								prevBuffer[k] = (paddingByte + 1) ^ prevBlock[k] ^ crackedData[k]
							}
						}
						break
					}
				}
			}
		}

		return crackedData
	}

	// Okay, let's try it out. Get an encrypted token.
	sample, iv := encrypt()

	// Decrypt it block-at-a-time
	plainText := []byte{}
	for i := 0; i < len(sample)/blockSize; i++ {
		curBlock := sample[i*blockSize : (i+1)*blockSize]
		prevBlock := iv
		if i > 0 {
			prevBlock = sample[(i-1)*blockSize : i*blockSize]
		}
		plainText = append(plainText, crack(curBlock, prevBlock)...)
	}

	// Unpad and display
	plainText, err = unpadPKCS7(plainText)
	fmt.Println(string(plainText))
	assertNoError(t, err)
	assertTrue(t, bytes.Equal(plainText[:5], []byte("00000")))
}

func TestS3C18(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	cipherText, err := encryptAESCTR([]byte("YELLOW SUBMARINE01234567ABCDEF"), key, 0)
	assertNoError(t, err)

	plainText, err := decryptAESCTR(cipherText, key, 0)
	assertNoError(t, err)
	assertTrue(t, bytes.Equal(plainText, []byte("YELLOW SUBMARINE01234567ABCDEF")))

	testString := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	cipherText, err = base64.StdEncoding.DecodeString(testString)
	assertNoError(t, err)

	plainText, err = decryptAESCTR(cipherText, key, 0)
	assertNoError(t, err)
	assertTrue(t, bytes.Equal(plainText, []byte("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ")))
}

func TestS3C19(t *testing.T) {
	data, err := ioutil.ReadFile("19.txt")
	assertNoError(t, err)

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	cipherTexts := make([][]byte, len(lines))

	minLen := 500
	for i, line := range lines {
		cipherText, err := base64.StdEncoding.DecodeString(line)
		assertNoError(t, err)
		cipherTexts[i] = cipherText
		if len(cipherText) < minLen {
			minLen = len(cipherText)
		}
	}

	// Crack as if repeating-key-XOR. To do that we create one long string
	// concatening the cipher texts trimmed to the minimum length.
	cipherText := []byte{}
	for _, line := range cipherTexts {
		cipherText = append(cipherText, line[:minLen]...)
	}

	// Create keySize buckets (km) -- each bucket represents N%keysize'th
	// character of the ciphertext
	keySize := minLen
	km := make([][]byte, keySize)
	for j := range km {
		km[j] = make([]byte, (len(cipherText)/keySize)+1)
	}

	// Bucket the cipherText into km
	for j := range cipherText {
		bucket := j % keySize
		loc := j / keySize
		km[bucket][loc] = byte(cipherText[j])
	}

	// Crack each bucket independently
	keys := []byte{}
	totalCost := float64(0)
	for j := range km {
		block := km[j]
		key, cost, _ := crackXORByteCost(block)
		keys = append(keys, key)
		totalCost += cost
	}

	plainText := decryptRepeatingKeyXOR(cipherText, keys)
	assertTrue(t, bytes.Equal(plainText[:minLen], []byte("i have met them at c")))
}

func TestS3C20(t *testing.T) {
	// We effectively solved 19 as 20
	TestS3C19(t)
}

func TestS3C21(t *testing.T) {
	twister := NewMT19937Twister()
	twister.Seed(42)

	fmt.Println(twister)

	rand1 := twister.Read()
	rand2 := twister.Read()
	rand3 := twister.Read()

	assertEquals(t, uint32(468307300), rand1)
	assertEquals(t, uint32(2413964465), rand2)
	assertEquals(t, uint32(3077182046), rand3)

	fmt.Println("First three numbers:", rand1, rand2, rand3)
	fmt.Println(twister)
}
