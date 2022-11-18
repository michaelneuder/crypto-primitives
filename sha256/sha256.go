// Implementation of SHA 256 in go based on https://en.wikipedia.org/wiki/SHA-2.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
)

const (
	h0 = uint32(0x6a09e667)
	h1 = uint32(0xbb67ae85)
	h2 = uint32(0x3c6ef372)
	h3 = uint32(0xa54ff53a)
	h4 = uint32(0x510e527f)
	h5 = uint32(0x9b05688c)
	h6 = uint32(0x1f83d9ab)
	h7 = uint32(0x5be0cd19)
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

func sha256(in string) [32]byte {
	out := [32]byte{}

	preprocessed := preprocess(in)

	// First just use a single chunk.
	w := [64][4]byte{}

	// Copy in original message.
	for i := 0; i < 16; i++ {
		copy(w[i][:], preprocessed[4*i:4*(i+1)])
	}
	fmt.Printf("%x\n", w[:])

	for i := 16; i < 64; i++ {
		var out, out2 uint32
		buf := bytes.NewBuffer(w[i-15][:])
		check(binary.Read(buf, binary.BigEndian, &out))
		s0 := bits.RotateLeft(uint(out), -7) ^ bits.RotateLeft(uint(out), -18) ^ (uint(out) >> 3)
		buf = bytes.NewBuffer(w[i-2][:])
		check(binary.Read(buf, binary.BigEndian, &out))
		s1 := bits.RotateLeft(uint(out), -17) ^ bits.RotateLeft(uint(out), -19) ^ (uint(out) >> 10)
		buf = bytes.NewBuffer(w[i-16][:])
		check(binary.Read(buf, binary.BigEndian, &out))
		buf = bytes.NewBuffer(w[i-7][:])
		check(binary.Read(buf, binary.BigEndian, &out2))

		wIns := [4]byte{}
		binary.BigEndian.PutUint32(wIns[:], out+uint32(s0)+out2+uint32(s1))
		w[i] = wIns
	}

	a := h0
	b := h1
	c := h2
	d := h3
	e := h4
	f := h5
	g := h6
	h := h7

	for i := 0; i < 64; i++ {
		S1 := bits.RotateLeft(uint(e), -6) ^ bits.RotateLeft(uint(e), -11) ^ bits.RotateLeft(uint(e), -25)
		ch := (uint(e) & uint(f)) ^ (^uint(e) & uint(g))

		wui32 := binary.BigEndian.Uint32(w[i][:])
		temp1 := h + uint32(S1) + uint32(ch) + k[i] + wui32
		S0 := bits.RotateLeft(uint(a), -2) ^ bits.RotateLeft(uint(a), -13) ^ bits.RotateLeft(uint(a), -22)
		maj := (a & b) ^ (a & c) ^ (b & c)
		temp2 := uint32(S0) + maj

		h = g
		g = f
		f = e
		e = d + temp1
		d = c
		c = b
		b = a
		a = temp1 + temp2
	}

	h0out := h0 + a
	h1out := h1 + b
	h2out := h2 + c
	h3out := h3 + d
	h4out := h4 + e
	h5out := h5 + f
	h6out := h6 + g
	h7out := h7 + h

	binary.BigEndian.PutUint32(out[:4], h0out)
	binary.BigEndian.PutUint32(out[4:8], h1out)
	binary.BigEndian.PutUint32(out[8:12], h2out)
	binary.BigEndian.PutUint32(out[12:16], h3out)
	binary.BigEndian.PutUint32(out[16:20], h4out)
	binary.BigEndian.PutUint32(out[20:24], h5out)
	binary.BigEndian.PutUint32(out[24:28], h6out)
	binary.BigEndian.PutUint32(out[28:32], h7out)
	return out
}

func main() {
	res := sha256("abc")
	fmt.Printf("res: \"abc\" = %x\n", hex.EncodeToString(res[:]))
	fmt.Printf("len = %d\n", len(res))
}
