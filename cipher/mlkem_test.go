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
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestKMAC256Vectors(t *testing.T) {
	key := fromHex(`
		404142434445464748494A4B4C4D4E4F
		505152535455565758595A5B5C5D5E5F`)
	custom := []byte("My Tagged Application")

	tests := []struct {
		name   string
		input  []byte
		size   int
		custom []byte
		want   []byte
	}{
		{
			name:   "short input with customization",
			input:  fromHex("00010203"),
			size:   64,
			custom: custom,
			want: fromHex(`
				20C570C31346F703C9AC36C61C03CB64
				C3970D0CFC787E9B79599D273A68D2F7
				F69D4CC3DE9D104A351689F27CF6F595
				1F0103F33F4F24871024D9C27773A8DD`),
		},
		{
			name: "long input without customization",
			input: fromHex(`
				000102030405060708090A0B0C0D0E0F
				101112131415161718191A1B1C1D1E1F
				202122232425262728292A2B2C2D2E2F
				303132333435363738393A3B3C3D3E3F
				404142434445464748494A4B4C4D4E4F
				505152535455565758595A5B5C5D5E5F
				606162636465666768696A6B6C6D6E6F
				707172737475767778797A7B7C7D7E7F
				808182838485868788898A8B8C8D8E8F
				909192939495969798999A9B9C9D9E9F
				A0A1A2A3A4A5A6A7A8A9AAABACADAEAF
				B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF
				C0C1C2C3C4C5C6C7`),
			size: 64,
			want: fromHex(`
				75358CF39E41494E949707927CEE0AF2
				0A3FF553904C86B08F21CC414BCFD691
				589D27CF5E15369CBBFF8B9A4C2EB178
				00855D0235FF635DA82533EC6B759B69`),
		},
	}

	for _, tt := range tests {
		got := kmac256(key, tt.input, tt.size, tt.custom)
		if !bytes.Equal(got, tt.want) {
			t.Errorf("%s: got %x, want %x", tt.name, got, tt.want)
		}
	}
}

func TestDeriveMLKEMUsesJOSEContext(t *testing.T) {
	sharedSecret := bytes.Repeat([]byte{0x42}, 32)

	got128 := DeriveMLKEM("A128GCM", sharedSecret, nil, 16)
	got256 := DeriveMLKEM("A256GCM", sharedSecret, nil, 32)

	if len(got128) != 16 {
		t.Fatalf("got %d-byte key, want 16", len(got128))
	}
	if len(got256) != 32 {
		t.Fatalf("got %d-byte key, want 32", len(got256))
	}
	if bytes.Equal(got128, got256[:16]) {
		t.Fatal("different alg/output-length contexts produced matching prefixes")
	}
}

func fromHex(s string) []byte {
	out, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		panic(err)
	}
	return out
}
