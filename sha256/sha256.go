// Implementation of SHA 256 in go based on https://en.wikipedia.org/wiki/SHA-2.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

func rotateRight(in, k uint32) uint {
	return (uint(in) >> k) | (uint(in) << (32 - k))
}

func preprocess(in string) []byte {
	lenIn := uint64(len(in) * 8)
	numZeros := (512 - (lenIn + 8 + 64)) / 8
	// fmt.Printf("numZeros=%d\n", numZeros)

	bytes := []byte(in)
	bytes = append(bytes, byte(0b10000000))
	for i := 0; i < int(numZeros); i++ {
		bytes = append(bytes, byte(0b00))
	}

	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, lenIn)
	// fmt.Printf("lenIN binary0=%b\n", b)
	for i := 0; i < 8; i++ {
		bytes = append(bytes, b[i])
	}
	// fmt.Printf("lenIN binary1=%b\n", bytes[64-8:])
	// fmt.Printf("*** preprocessed %v\n", bytes)
	// fmt.Printf("*** length %v\n", len(bytes))
	return bytes
}

func sha256(in string) [32]byte {
	if len(in) > 64 {
		panic("message too long! only support messages < 64 characters")
	}
	preprocessed := preprocess(in)

	fmt.Printf("*** padded message=%x\n", preprocessed)
	fmt.Printf("*** padded message=%08b\n", preprocessed)

	// First just use a single chunk.
	w := [64][4]byte{}

	// Copy in original message.
	for i := 0; i < 16; i++ {
		copy(w[i][:], preprocessed[4*i:4*(i+1)])
	}

	for i := 16; i < 64; i++ {
		var out0, out1, temp uint32
		buf := bytes.NewBuffer(w[i-7][:])
		check(binary.Read(buf, binary.BigEndian, &out0))
		buf = bytes.NewBuffer(w[i-16][:])
		check(binary.Read(buf, binary.BigEndian, &out1))

		buf = bytes.NewBuffer(w[i-15][:])
		check(binary.Read(buf, binary.BigEndian, &temp))
		s0 := rotateRight(temp, 7) ^ rotateRight(temp, 18) ^ uint(temp>>3)

		fmt.Printf("*** i-15: %d, s0: %d\n", i-15, s0)
		buf = bytes.NewBuffer(w[i-2][:])
		check(binary.Read(buf, binary.BigEndian, &temp))
		s1 := rotateRight(temp, 17) ^ rotateRight(temp, 19) ^ uint(temp>>10)

		// if i == 17 {
		// 	buf = bytes.NewBuffer(w[i-2][:])
		// 	check(binary.Read(buf, binary.BigEndian, &temp))
		// 	fmt.Printf("*** first rotation of %d=%d\n", temp, rotateRight(temp, 17))
		// 	fmt.Printf("*** term1=%d,term2=%d,term3=%d,term4=%d\n", s0, out0, s1, out1)
		// }

		wIns := [4]byte{}
		binary.BigEndian.PutUint32(wIns[:], out0+uint32(s0)+out1+uint32(s1))
		w[i] = wIns
	}
	panic("here")
	fmt.Printf("*** message schedule=%x\n", w[:])

	a := h0
	b := h1
	c := h2
	d := h3
	e := h4
	f := h5
	g := h6
	h := h7

	for i := 0; i < 64; i++ {
		S1 := rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25)
		ch := (uint(e) & uint(f)) ^ (^uint(e) & uint(g))

		wui32 := binary.BigEndian.Uint32(w[i][:])
		temp1 := (uint(h) + S1 + ch + uint(k[i]) + uint(wui32)) % uint(1<<32)
		S0 := rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22)
		maj := (uint(a) & uint(b)) ^ (uint(a) & uint(c)) ^ (uint(b) & uint(c))
		temp2 := (S0 + maj) % uint(1<<32)

		if i == 63 {
			// fmt.Printf("*** e=%d\n", e)
			// (in >> k) | (in << (32 - k))
			// fmt.Printf("*** shift e 6=%d\n", e>>6)
			// fmt.Printf("*** shift e left 26=%d\n", uint(e)<<26)
			// fmt.Printf("*** rot e 6=%d\n", rotateRight(e, 6))
			// fmt.Printf("*** S1=%d\n", S1)
			// fmt.Printf("*** c1=%d\n", ch)
			// fmt.Printf("*** t1=%d\n", temp1)
			// fmt.Printf("*** t2=%d\n", temp2)
		}
		h = g
		g = f
		f = e
		e = uint32((uint(d) + temp1) % uint(1<<32))
		d = c
		c = b
		b = a
		a = uint32((temp1 + temp2) % uint(1<<32))
	}

	h0out := uint32((uint(h0) + uint(a)) % uint(1<<32))
	h1out := uint32((uint(h1) + uint(b)) % uint(1<<32))
	h2out := uint32((uint(h2) + uint(c)) % uint(1<<32))
	h3out := uint32((uint(h3) + uint(d)) % uint(1<<32))
	h4out := uint32((uint(h4) + uint(e)) % uint(1<<32))
	h5out := uint32((uint(h5) + uint(f)) % uint(1<<32))
	h6out := uint32((uint(h6) + uint(g)) % uint(1<<32))
	h7out := uint32((uint(h7) + uint(h)) % uint(1<<32))

	// fmt.Printf("*** a=%d\n", a)
	// fmt.Printf("*** h0out=%d\n", h0out)
	// fmt.Printf("*** h1out=%d\n", h1out)
	// fmt.Printf("*** h2out=%d\n", h2out)
	// fmt.Printf("*** h3out=%d\n", h3out)
	// fmt.Printf("*** h4out=%d\n", h4out)
	// fmt.Printf("*** h5out=%d\n", h5out)
	// fmt.Printf("*** h6out=%d\n", h6out)
	// fmt.Printf("*** h7out=%d\n", h7out)

	out := [32]byte{}
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
	fmt.Printf("%0x\n", res[:])
}
