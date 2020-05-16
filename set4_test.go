package cryptopals

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/rand"
	"regexp"
	"testing"
	"time"

	"github.com/0xfe/cryptopals/md4"
	"github.com/0xfe/cryptopals/sha1"
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

func TestS4C27(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	key := make([]byte, 16)
	_, err := rand.Read(key)
	assertNoError(t, err)

	// Make IV the same as the key. This challenge demonstrates why it's
	// bad to set the IV to the key.
	iv := make([]byte, 16)
	copy(iv, key)

	fmt.Println("Random key `:", key)

	encrypt := func(input []byte) ([]byte, error) {
		sanitizedInput := []byte{}
		for _, c := range input {
			if c != ';' && c != '=' {
				sanitizedInput = append(sanitizedInput, c)
			}
		}

		cipherText, err := encryptAESCBC(sanitizedInput, key, iv)
		if err != nil {
			return nil, fmt.Errorf("could not CBC encrypt: %w", err)
		}

		return cipherText, nil
	}

	decrypt := func(cipherText []byte) ([]byte, error) {
		plainText, err := decryptAESCBC(cipherText, key, iv)
		if err != nil {
			return nil, fmt.Errorf("could not CBC decrypt: %w", err)
		}

		for _, c := range plainText {
			if c > 127 {
				return nil, fmt.Errorf("Bad chars found: %s", plainText)
			}
		}

		return plainText, nil
	}

	// Encrypt random plaintext to get 3 cipher text blocks: C1, C2, and C3.
	cipherText, err := encrypt([]byte("jsdlknm0adddddh0f7h34huijnefoasuidhfoiusdnfoudnf"))
	assertNoError(t, err)

	// Zero out second block of ciphertext
	copy(cipherText[16:32], make([]byte, 16))

	// Copy first block into third block.
	copy(cipherText[32:], cipherText[0:16])

	// Decrypt to get plain text blocks: P1, P2, and P3
	_, err = decrypt(cipherText)
	assertHasError(t, err)

	// Extract plainText from error message (Remove "Bad chars found: ")
	plainText := []byte(fmt.Sprintf("%s", err)[17:])

	// P1 ^ P3 should be the key. This is because:
	// P1 = IV ^ C1
	// P3 = 0 ^ C1
	// P1 ^ P3 = IV
	// and IV = key!
	crackedKey := make([]byte, 16)
	for i, c := range plainText[:16] {
		crackedKey[i] = c ^ plainText[32+i]
	}
	fmt.Println("Cracked key:", crackedKey)
	assertTrue(t, bytes.Equal(key, crackedKey))
}

func TestS4C28(t *testing.T) {
	secret := []byte("foobar")
	hash := func(message []byte) []byte {
		hash := sha1.Sum(append(secret, message...))
		return hash[:]
	}

	digest := hex.EncodeToString(hash([]byte("message")))
	assertEquals(t, digest, "4bfe2ee07ff3ee5cfc4dee81985eb754e946df93")
}

// Get SHA-1/MD4 padding bytes for msg. Set `bigEndian` to true for
// SHA-1.
func getPadding(msg []byte, bigEndian bool) []byte {
	// Message sizes are 64-bytes (512 bits)
	// Need room for 8 bytes (64 bits) for integer length of message

	// Calculate message length plus 1 (for the required "1" bit)
	l := len(msg)*8 + 1

	// Calculate bytes remaining for the block
	r := 512 - (l % 512)

	// Figure out how many zero bits to add
	zeroBitsToAdd := 1
	if r > 64 {
		zeroBitsToAdd = r - 64
	} else {
		zeroBitsToAdd = r + (512 - 64)
	}

	// Figure out how many total bytes of padding:
	// "1" + n "0"s + 8-byte integer
	paddingLen := ((1 + zeroBitsToAdd) / 8) + 8
	paddingBytes := make([]byte, paddingLen)
	paddingBytes[0] |= 1 << 7

	if bigEndian {
		binary.BigEndian.PutUint64(paddingBytes[paddingLen-8:], uint64(len(msg)*8))
	} else {
		binary.LittleEndian.PutUint64(paddingBytes[paddingLen-8:], uint64(len(msg)*8))
	}
	return paddingBytes
}

func TestSHA1Padding(t *testing.T) {
	// Return padded msg (using SHA-1 padding scheme)
	pad := func(msg []byte) []byte {
		return append(msg, getPadding(msg, true)...)
	}

	// Pad random messages of length 0 -> 1025 and run tests against them.
	for l := 0; l < 1025; l++ {
		// Generate random message of length l
		msg := make([]byte, l)
		_, err := rand.Read(msg)
		assertNoError(t, err)

		// Pad it
		paddedMsg := pad(msg)

		// Verify that there's a "1" bit immediately after the message
		assertTrue(t, paddedMsg[len(msg)]&(1<<7) > 0)

		// Verify that the last 64-bits represent the length of the original message
		assertEquals(t, uint64(len(msg)*8), binary.BigEndian.Uint64(paddedMsg[len(paddedMsg)-8:]))

		// Verify that the padded message aligns to a 512-bit (64-byte) boundary
		assertEquals(t, 0, len(paddedMsg)%64)
	}

}

func TestMD4Padding(t *testing.T) {
	// Return padded msg (using SHA-1 padding scheme)
	pad := func(msg []byte) []byte {
		return append(msg, getPadding(msg, false)...)
	}

	// Pad random messages of length 0 -> 1025 and run tests against them.
	for l := 0; l < 1025; l++ {
		// Generate random message of length l
		msg := make([]byte, l)
		_, err := rand.Read(msg)
		assertNoError(t, err)

		// Pad it
		paddedMsg := pad(msg)

		// Verify that there's a "1" bit immediately after the message
		assertTrue(t, paddedMsg[len(msg)]&(1<<7) > 0)

		// Verify that the last 64-bits represent the length of the original message
		assertEquals(t, uint64(len(msg)*8), binary.LittleEndian.Uint64(paddedMsg[len(paddedMsg)-8:]))

		// Verify that the padded message aligns to a 512-bit (64-byte) boundary
		assertEquals(t, 0, len(paddedMsg)%64)
	}

}

func TestS4C29(t *testing.T) {
	// SHA-1 keyed MAC with secret "foobar"
	secret := []byte("foobar")
	hmac := func(message []byte) []byte {
		hash := sha1.Sum(append(secret, message...))
		return hash[:]
	}

	// Return a SHA1 hash of 'message'
	hash := func(message []byte, args ...uint32) []byte {
		hash := sha1.Sum(message, args...)
		return hash[:]
	}

	// This is the original message that is sent to the server, and 'md' is the returned HMAC
	// effectively authorizing this token.
	params := []byte(`comment1=cooking%20MCs;comment2=%20like%20a%20pound%20of%20bacon;userdata=foo`)
	md := hmac(params)

	// To perform a length-extension attack, we first slice out the five 32-bit components of
	// the SHA-1 digest, and use it as an initializer into our own SHA-1 calculator. This
	// means that as you extend the message, you can continue hashing from this 160-bit state.
	//
	// Since the prefix of the original message is the secret, the hash is valid for any extension
	// to the original message.
	a := binary.BigEndian.Uint32(md[0:4])
	b := binary.BigEndian.Uint32(md[4:8])
	c := binary.BigEndian.Uint32(md[8:12])
	d := binary.BigEndian.Uint32(md[12:16])
	e := binary.BigEndian.Uint32(md[16:20])

	found := false
	foundString := []byte{}
	foundMD := []byte{}

	// We don't know the lengh of the secret, but the message was padded to a block boundary. Here
	// we'll try 64, 128, ... -byte boundaries. We need to specify this length to the SHA-1 calculator
	// so it knows where to continue from.
	for numBlocks := 1; !found && numBlocks < 5; numBlocks++ {
		blockLen := numBlocks * 64
		attackString := []byte(";admin=true")

		// Construct a new hash with the appended attack string, starting from the
		// SHA-1 hash of the original string.
		targetMD := hash(attackString, a, b, c, d, e, uint32(blockLen))

		// We're actually done here -- targetMD is the right hash, we now need to find
		// the string that hashes to this value. To do this we only need to figure out
		// the padding applied to the original message (which depends on the length of
		// the secret.)

		// Assume the secret is between 0 and 20 characters
		for l := len(params); l < len(params)+20; l++ {
			// Create a dummy string of length l, and get it's padding bytes.
			padding := getPadding(make([]byte, l), true)

			// Insert the padding between the original string and the attack string
			attack := append(append(params, padding...), attackString...)

			// See if you get the same hash as targetMD
			attackHash := hmac(attack)
			if bytes.Equal(targetMD, attackHash) {
				found = true
				foundString = attack
				foundMD = attackHash
				break
			}
		}
	}

	fmt.Println("Found hash", hex.EncodeToString(foundMD), "for", foundString)
	assertTrue(t, found)
}

func TestS4C30(t *testing.T) {
	// This is pretty much the same attack as the previous challenge, except using
	// MD4 instead of SHA1. The mechanism of the attack is the same, however:
	//
	//  * SHA1 is big-endian, while MD4 is little-endian
	//  * SHA1 has 5 state words, while MD4 has 4 state words.

	// MD4 keyed MAC with secret "foobar"
	secret := []byte("foobar")
	hmac := func(message []byte) []byte {
		hash := md4.Sum(append(secret, message...))
		fmt.Println("HMAC:", hex.EncodeToString(hash))
		return hash[:]
	}

	// Return a MD4 hash of 'message'
	hash := func(message []byte, args ...uint32) []byte {
		hash := md4.Sum(message, args...)
		fmt.Println("HASH:", hex.EncodeToString(hash))
		return hash[:]
	}

	// This is the original message that is sent to the server, and 'md' is the returned HMAC
	// effectively authorizing this token.
	params := []byte(`comment1=cooking%20MCs;comment2=%20like%20a%20pound%20of%20bacon;userdata=foo`)
	md := hmac(params)

	// To perform a length-extension attack, we first slice out the four 32-bit components of
	// the MD4 digest, and use it as an initializer into our own MD4 calculator. This
	// means that as you extend the message, you can continue hashing from this 128-bit state.
	//
	// Since the prefix of the original message is the secret, the hash is valid for any extension
	// to the original message.
	a := binary.LittleEndian.Uint32(md[0:4])
	b := binary.LittleEndian.Uint32(md[4:8])
	c := binary.LittleEndian.Uint32(md[8:12])
	d := binary.LittleEndian.Uint32(md[12:16])

	found := false
	foundString := []byte{}
	foundMD := []byte{}

	// We don't know the lengh of the secret, but the message was padded to a block boundary. Here
	// we'll try 64, 128, ... -byte boundaries. We need to specify this length to the MD4 calculator
	// so it knows where to continue from.
	for numBlocks := 1; !found && numBlocks < 5; numBlocks++ {
		blockLen := numBlocks * 64
		attackString := []byte(";admin=true")

		// Construct a new hash with the appended attack string, starting from the
		// MD4 hash of the original string.
		targetMD := hash(attackString, a, b, c, d, uint32(blockLen))

		// We're actually done here -- targetMD is the right hash, we now need to find
		// the string that hashes to this value. To do this we only need to figure out
		// the padding applied to the original message (which depends on the length of
		// the secret.)

		// Assume the secret is between 0 and 20 characters
		for l := len(params); l < len(params)+20; l++ {
			// Create a dummy string of length l, and get it's padding bytes.
			padding := getPadding(make([]byte, l), false)

			// Insert the padding between the original string and the attack string
			attack := append(append(params, padding...), attackString...)

			// See if you get the same hash as targetMD
			attackHash := hmac(attack)
			if bytes.Equal(targetMD, attackHash) {
				found = true
				foundString = attack
				foundMD = attackHash
				break
			}
		}
	}

	fmt.Println("Found hash", hex.EncodeToString(foundMD), "for", foundString)
	assertTrue(t, found)
}
