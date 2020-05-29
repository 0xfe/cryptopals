package cryptopals

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func TestS3C17(t *testing.T) {
	blockSize := 16
	rand.Seed(time.Now().UnixNano())

	// Read random strings from file
	data, err := ioutil.ReadFile("data/17.txt")
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
				// Set the cipherText for the previous block at position i to j, trying
				// every value from 0 - 255.
				prevBuffer[i] = byte(j)
				if decrypt(block, prevBuffer) {
					// If we're here, then there's no padding error, which means that the
					// byte at position i == paddingByte (according to PKCS7 padding rules.)
					//
					// Because:
					//   CBC decryption = prevEncryptedBlock[i] XOR curPlaintextBlock[i], and
					//   curPlaintextBlock[i] = paddingByte (which we just discovered)
					//   originalPlaintextBlock[i] = paddingByte ^ j ^ prevEncryptedBlock[i]

					crackedByte := paddingByte ^ byte(j) ^ prevBlock[i]
					if byte(j) != prevBlock[i] || paddingByte != 1 {
						crackedData[i] = crackedByte

						// Update previous buffer for next padding byte. When going from 1-byte
						// padding to 2-byte padding (or 2 to 3, 3 to 4, etc.), update all the 0x01 padding
						// values to 0x02 (or 0x02 to 0x03, etc.)
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
	data, err := ioutil.ReadFile("data/19.txt")
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

func TestS3C22(t *testing.T) {
	unixTime := func() uint32 {
		return uint32(time.Now().Unix() & 0xFFFFFFFF)
	}

	randomInt := func(delay1, delay2 time.Duration) uint32 {
		time.Sleep(delay1)
		rng := NewMT19937Twister()
		rng.Seed(unixTime())
		time.Sleep(delay2)

		return rng.Read()
	}

	fmt.Println("Generating random value..")
	val := randomInt(time.Second, time.Second)
	fmt.Println("Val:", val)

	// Find seed from val

	now := unixTime()
	found := false
	for ts := now; ts > now-5000; ts-- {
		rng := NewMT19937Twister()
		rng.Seed(ts)
		testVal := rng.Read()
		if testVal == val {
			fmt.Println("Found seed:", ts)
			found = true
			break
		}
	}

	assertTrue(t, found)
}

func TestS3C23(t *testing.T) {
	rng := NewMT19937Twister()
	rng.Seed(42)

	// Test temper/untemper
	val := rng.Read()
	fmt.Printf("Original      : %032b %d\n", val, val)
	tempered := rng.temper(val)
	fmt.Printf("Tempered      : %032b %d\n", tempered, tempered)
	untempered := rng.untemper(tempered)
	fmt.Printf("Untempered    : %032b %d\n", untempered, untempered)
	assertEquals(t, val, untempered)

	rng = NewMT19937Twister()
	rng.Seed(uint32(time.Now().UnixNano()))

	// Tap internal state of PRNG
	MT := make([]uint32, 624)
	for i := 0; i < 624; i++ {
		MT[i] = rng.untemper(rng.Read())
	}

	// Create a new PRNG and splice in reconstructed state
	newRng := NewMT19937Twister()
	newRng.SetMT(MT)

	// Verify that both PRNGs now generate the same future values
	assertEquals(t, rng.Read(), newRng.Read())
}

func TestS3C24(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	encrypt := func(plainText []byte, seed uint16) []byte {
		rng := NewMT19937Twister()
		rng.Seed(uint32(seed))

		cipherText := make([]byte, len(plainText))
		keyStream := make([]byte, 4)
		j := 4 // pointer into keyStream. Start past end.
		for i := 0; i < len(plainText); i++ {
			// Read new value from RNG and update keystream.
			if j >= 4 {
				val := rng.Read()
				binary.LittleEndian.PutUint32(keyStream, val)
				j = 0
			}

			// XOR keystream position with plaintext
			cipherText[i] = plainText[i] ^ keyStream[j]
			j++
		}

		return cipherText
	}

	decrypt := encrypt

	// Test encryption / decryption
	seed := uint16(time.Now().UnixNano() & 0xFFFF)
	fmt.Printf("Seed      : %032b %d\n", seed, seed)
	cipherText := encrypt([]byte("foobar"), seed)
	plainText := decrypt(cipherText, seed)
	assertTrue(t, bytes.Equal(plainText, []byte("foobar")))

	// Encrypt known plaintext with random prefix
	numChars := rand.Intn(20) + 1
	randChars := make([]byte, numChars)
	_, err := rand.Read(randChars)
	assertNoError(t, err)

	plainText = append(randChars, []byte("AAAAAAAAAAAAAA")...)
	cipherText = encrypt(plainText, seed)

	// Crack seed by brute-forcing all possible 16-bit seed values
	foundSeed := uint16(0)
	for i := uint16(0); i < math.MaxUint16; i++ {
		pt := decrypt(cipherText, i)
		if bytes.Contains(pt, []byte("AAAAAAAAAAAAAA")) {
			foundSeed = i
			break
		}
	}

	fmt.Println("Found seed: ", foundSeed)
	assertEquals(t, seed, foundSeed)

	// Generate random password reset token
	genToken := func(seedWithTS bool) string {
		token := make([]byte, 22)
		_, err := rand.Read(token)
		assertNoError(t, err)
		copy(token[:6], []byte("token="))

		seed := uint16(time.Now().Unix())
		if !seedWithTS {
			seed = uint16(rand.Int31())
		}

		encryptedToken := encrypt(token, seed)
		stringToken := base64.StdEncoding.EncodeToString(encryptedToken)
		fmt.Println("Generated token: ", stringToken)
		return stringToken
	}

	isMT19937Token := func(token string) bool {
		encryptedToken, err := base64.StdEncoding.DecodeString(token)
		assertNoError(t, err)

		now := uint16(time.Now().Unix())
		for ts := now; ts > now-60; ts-- {
			plainText := decrypt(encryptedToken, ts)
			if bytes.Equal(plainText[:6], []byte("token=")) {
				return true
			}
		}

		return false
	}

	// Generate a token seeded with the current time stamp
	token := genToken(true)
	assertTrue(t, isMT19937Token(token))

	// Generate a token seeded with Golang's RNG
	token = genToken(false)
	assertFalse(t, isMT19937Token(token))
}
