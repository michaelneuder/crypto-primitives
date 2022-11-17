// Implementation of SHA 256 in go based on https://en.wikipedia.org/wiki/SHA-2.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
)

const (
	h0 = 0x6a09e667
	h1 = 0xbb67ae85
	h2 = 0x3c6ef372
	h3 = 0xa54ff53a
	h4 = 0x510e527f
	h5 = 0x9b05688c
	h6 = 0x1f83d9ab
	h7 = 0x5be0cd19
)

var k [64]uint32 = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func preprocess(in string) []byte {
	bytes := []byte(in)
	bytes = append(bytes, byte(0b10000000))
	for i := 0; i < 52; i++ {
		bytes = append(bytes, byte(0b0))
	}
	for i := 0; i < 7; i++ {
		bytes = append(bytes, byte(0b0))
	}
	bytes = append(bytes, byte(0b00011000))
	return bytes
}

func sha256(in string) [64]byte {
	out := [64]byte{}

	preprocessed := preprocess(in)

	// First just use a single chunk.
	w := [64][4]byte{}

	// Copy in original message.
	for i := 0; i < 16; i++ {
		copy(w[i][:], preprocessed[4*i:4*(i+1)])
	}
	fmt.Printf("%x\n", w[:])

	for i := 16; i < 64; i++ {
		var out uint
		buf := bytes.NewBuffer(w[i-15][:])
		check(binary.Read(buf, binary.BigEndian, &out))
		s0 := bits.RotateLeft(out, -7) ^ bits.RotateLeft(out, -18) ^ (out >> 3)
		// s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
		// s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
		// w[i] := w[i-16] + s0 + w[i-7] + s1
	}
	return out
}

func main() {
	// out := sha256("hello")
	// fmt.Printf("output: %x", out)

	res := sha256("abc")
	fmt.Printf("preprocess: \"abc\" = %08b\n", res)
	fmt.Printf("len = %d\n", len(res))
}
