package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
)

func assertNoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("want no error, got error: %v", err)
	}
}

func assertEquals(t *testing.T, want interface{}, got interface{}) {
	if want != got {
		t.Errorf("want: %v, got %v", want, got)
	}
}

func TestChallenge1(t *testing.T) {
	inHex := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	wantBase64 := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	bytes, err := hex.DecodeString(inHex)
	assertNoError(t, err)
	gotBase64 := base64.StdEncoding.EncodeToString(bytes)

	assertEquals(t, wantBase64, gotBase64)
}

func TestChallenge2(t *testing.T) {
	inHex1 := "1c0111001f010100061a024b53535009181c"
	inHex2 := "686974207468652062756c6c277320657965"
	wantHex := "746865206b696420646f6e277420706c6179"

	bytes1, err := hex.DecodeString(inHex1)
	assertNoError(t, err)
	bytes2, err := hex.DecodeString(inHex2)
	assertNoError(t, err)

	out := make([]byte, len(bytes1))
	for i := range bytes1 {
		out[i] = bytes1[i] ^ bytes2[i]
	}

	gotHex := hex.EncodeToString(out)
	assertEquals(t, wantHex, gotHex)
}

func TestChallenge3(t *testing.T) {
	cipherTextHex := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	cipherText, err := hex.DecodeString(cipherTextHex)
	assertNoError(t, err)

	bestKey, bestCost, bestString := crackXORByteCost(cipherText)

	fmt.Println(bestKey, bestCost, bestString)
	assertEquals(t, bestKey, byte(88))
	assertEquals(t, bestString, "Cooking MC's like a pound of bacon")
}

func TestChallenge4(t *testing.T) {
	data, err := ioutil.ReadFile("4.txt")
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
