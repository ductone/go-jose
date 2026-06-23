/*-
 * Copyright 2026 Duct One Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package josecipher

import (
	"crypto/sha3"
	"encoding/binary"
)

const kmac256Rate = 136

// DeriveMLKEM derives a JOSE key from an ML-KEM shared secret using KMAC256.
func DeriveMLKEM(alg string, sharedSecret, suppPrivInfo []byte, size int) []byte {
	algID := lengthPrefixed([]byte(alg))
	suppPubInfo := make([]byte, 4)
	binary.BigEndian.PutUint32(suppPubInfo, uint32(size)*8)

	x := make([]byte, 0, len(algID)+len(suppPubInfo)+len(suppPrivInfo))
	x = append(x, algID...)
	x = append(x, suppPubInfo...)
	x = append(x, suppPrivInfo...)

	return kmac256(sharedSecret, x, size, nil)
}

func kmac256(key, input []byte, size int, customization []byte) []byte {
	cshake := sha3.NewCSHAKE256([]byte("KMAC"), customization)
	_, _ = cshake.Write(bytepad(encodeString(key), kmac256Rate))
	_, _ = cshake.Write(input)
	_, _ = cshake.Write(rightEncode(uint64(size * 8)))

	out := make([]byte, size)
	_, _ = cshake.Read(out)
	return out
}

func bytepad(encoded []byte, w int) []byte {
	out := append(leftEncode(uint64(w)), encoded...)
	if rem := len(out) % w; rem != 0 {
		out = append(out, make([]byte, w-rem)...)
	}
	return out
}

func encodeString(s []byte) []byte {
	out := leftEncode(uint64(len(s) * 8))
	out = append(out, s...)
	return out
}

func leftEncode(x uint64) []byte {
	var tmp [9]byte
	n := 1
	for i := x; i > 255; i >>= 8 {
		n++
	}
	tmp[0] = byte(n)
	for i := n; i > 0; i-- {
		tmp[i] = byte(x)
		x >>= 8
	}
	return tmp[:n+1]
}

func rightEncode(x uint64) []byte {
	var tmp [9]byte
	n := 1
	for i := x; i > 255; i >>= 8 {
		n++
	}
	for i := n - 1; i >= 0; i-- {
		tmp[i] = byte(x)
		x >>= 8
	}
	tmp[n] = byte(n)
	return tmp[:n+1]
}
