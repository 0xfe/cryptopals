## Cryptopals Crypto Challenge Solutions in Go

*Author*: Mohit Cheppudira <mohit@muthanna.com> 2020

This repository consists of my documented [Go](https://golang.org) solutions of the [Cyptopals Cryptography Challenges](https://cryptopals.com/) (formerly known as the Matsano Crypto Challenges).

These challenges have been implemented as Go tests to make it easy to explore and debug.

### The files

* `setN_test.go` - Solutions to the challenges in set `N`.
* `aes.go` - My implementations of various AES operation modes (ECB, CBC, CTR), along with some block-size detection and cracking code.
* `sha1/sha1.go` - A modified implementation of Golang's SHA1 to tap and extract hashing state
* `md4/md4.go` - A modified implementation of Golang's MD4 to tap and extract hashing state
* `prng.go` - My implementation of the Mersenne Twister PRNG
* `rsa.go` - My implementation of RSA (keygen, encrypt, decrypt, sign, verify, pad, unpad). Uses OpenSSL to find large random primes.
* `helpers.go` - Various helper functions across the codebase: hamming distance, modular exponentiation, frequency analysis, PKCS7 padding, cube root, etc.
* `data/*.txt` - Data files as part of each challenge.

### To run:

Note that some challenges have been disabled because they're very slow (e.g., timing attacks, brute force attacks). You can re-enable them within the test as you need.

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