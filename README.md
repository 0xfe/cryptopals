## Cryptopals Crypto Challenge Solutions in Go

*Author*: Mohit Cheppudira <mohit@muthanna.com> 2020

This repository consists of my documented [Go](https://golang.org) solutions to all 6 sets of the original [Cyptopals Cryptography Challenges](https://cryptopals.com/) (formerly known as the Matsano Crypto Challenges).

These challenges have been implemented as Go tests to make it easy to explore and debug.

### Livestream

I've been livecoding these challenges on Twitch -- if you want to join in, watch at https://twitch.tv/11111110b.

Be warned: some of these sessions are looooooong!

### The Files

* `setN_test.go` - Solutions to the challenges in set `N`.
* `aes.go` - My implementations of various AES operation modes (ECB, CBC, CTR), along with some block-size detection and cracking code.
* `sha1/sha1.go` - A modified implementation of Golang's SHA1 to tap and extract hashing state
* `md4/md4.go` - A modified implementation of Golang's MD4 to tap and extract hashing state
* `prng.go` - My implementation of the Mersenne Twister PRNG
* `rsa.go` - My implementation of RSA (keygen, encrypt, decrypt, sign, verify, pad, unpad). Uses OpenSSL to find large random primes.
* `dsa.go` - My implementation of DSA (keygen, sign, verify)
* `pkcs7.go` - Functions implementing PKCS7 padding and unpadding.
* `english.go` - English plaintext-detection using frequency analysis.
* `bigmath.go` - Modular arithmetic with big integers (exponention, cube root, ceil/floor division, etc.)
* `helpers.go` - Various helper functions across the codebase: hamming distance, blocksize detection, padding, etc.
* `data/*.txt` - Data files as part of each challenge.

### To Run:

Note that some challenges have been disabled because they're very slow (e.g., timing attacks, brute force attacks, bleichenbacher98). You can re-enable them within the test as you need.

#### Run all challenges:

```
go test -v
```

#### Run a specific challenge:

```
# Run challenge 38
go test --run C38

# Run all challenges in set 5
go test --run S5
```