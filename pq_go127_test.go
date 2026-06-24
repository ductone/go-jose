//go:build go1.27

/*-
 * Copyright 2014 Square Inc.
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

package jose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestMLDSARoundTripsJWS(t *testing.T) {
	algs := []struct {
		alg    SignatureAlgorithm
		params mldsa.Parameters
	}{
		{ML_DSA_44, mldsa.MLDSA44()},
		{ML_DSA_65, mldsa.MLDSA65()},
		{ML_DSA_87, mldsa.MLDSA87()},
	}

	for _, tc := range algs {
		key, err := mldsa.GenerateKey(tc.params)
		if err != nil {
			t.Fatal(err)
		}
		for _, serializer := range []func(*JSONWebSignature) (string, error){
			func(obj *JSONWebSignature) (string, error) { return obj.CompactSerialize() },
			func(obj *JSONWebSignature) (string, error) { return obj.FullSerialize(), nil },
		} {
			if err := RoundtripJWS(tc.alg, serializer, func(obj *JSONWebSignature) {}, key, key.PublicKey(), "test_nonce"); err != nil {
				t.Errorf("%s round trip failed: %v", tc.alg, err)
			}
		}
	}
}

func TestMLDSAEmbeddedJWK(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(SigningKey{Algorithm: ML_DSA_44, Key: key}, &SignerOptions{EmbedJWK: true})
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	serialized := obj.FullSerialize()
	parsed, err := ParseSigned(serialized, []SignatureAlgorithm{ML_DSA_44})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Signatures[0].Header.JSONWebKey == nil {
		t.Fatal("embedded JWK missing")
	}
	if _, err = parsed.Verify(parsed.Signatures[0].Header.JSONWebKey); err != nil {
		t.Fatalf("Verify with embedded JWK: %v", err)
	}
}

func TestMLDSAAKPJWKRoundTrip(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	jwk := JSONWebKey{Key: key, Algorithm: string(ML_DSA_65), Use: "sig", KeyID: "mldsa"}
	marshaled, err := jwk.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	var parsed JSONWebKey
	if err = parsed.UnmarshalJSON(marshaled); err != nil {
		t.Fatal(err)
	}
	parsedKey, ok := parsed.Key.(*mldsa.PrivateKey)
	if !ok {
		t.Fatalf("parsed key type = %T, want *mldsa.PrivateKey", parsed.Key)
	}
	if !bytes.Equal(parsedKey.Bytes(), key.Bytes()) {
		t.Fatal("private key seed mismatch after JWK round trip")
	}
	if parsed.Algorithm != string(ML_DSA_65) || parsed.Use != "sig" || parsed.KeyID != "mldsa" {
		t.Fatalf("metadata mismatch after JWK round trip: %#v", parsed)
	}

	public := parsed.Public()
	if !public.IsPublic() || !public.Valid() {
		t.Fatal("public ML-DSA JWK should be valid and public")
	}

	pubMarshaled, err := public.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var parsedPublic JSONWebKey
	if err = parsedPublic.UnmarshalJSON(pubMarshaled); err != nil {
		t.Fatal(err)
	}
	if _, ok = parsedPublic.Key.(*mldsa.PublicKey); !ok {
		t.Fatalf("parsed public key type = %T, want *mldsa.PublicKey", parsedPublic.Key)
	}

	thumbprint, err := public.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	expectedInput, err := akpThumbprintInput(string(ML_DSA_65), key.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	expectedThumbprint := sha256.Sum256([]byte(expectedInput))
	if !bytes.Equal(thumbprint, expectedThumbprint[:]) {
		t.Fatal("AKP thumbprint mismatch")
	}
}

func TestMLDSAAKPJWKRejectsMismatchedPrivateKey(t *testing.T) {
	keyA, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}

	raw := `{"kty":"AKP","alg":"ML-DSA-44","pub":"` +
		base64.RawURLEncoding.EncodeToString(keyA.PublicKey().Bytes()) +
		`","priv":"` +
		base64.RawURLEncoding.EncodeToString(keyB.Bytes()) +
		`"}`
	var jwk JSONWebKey
	if err = jwk.UnmarshalJSON([]byte(raw)); err == nil {
		t.Fatal("expected mismatched ML-DSA pub/priv JWK to fail")
	}
}

func TestCompositeRoundTripsJWS(t *testing.T) {
	algs := []SignatureAlgorithm{
		ML_DSA_44_ES256,
		ML_DSA_65_ES256,
		ML_DSA_87_ES384,
		ML_DSA_44_Ed25519,
		ML_DSA_65_Ed25519,
	}

	for _, alg := range algs {
		key := generateCompositeTestKey(t, alg)
		for _, serializer := range []func(*JSONWebSignature) (string, error){
			func(obj *JSONWebSignature) (string, error) { return obj.CompactSerialize() },
			func(obj *JSONWebSignature) (string, error) { return obj.FullSerialize(), nil },
		} {
			if err := RoundtripJWS(alg, serializer, func(obj *JSONWebSignature) {}, key, key.Public().(*CompositePublicKey), "test_nonce"); err != nil {
				t.Errorf("%s round trip failed: %v", alg, err)
			}
		}
	}
}

func TestCompositeEmbeddedJWK(t *testing.T) {
	key := generateCompositeTestKey(t, ML_DSA_44_Ed25519)
	signer, err := NewSigner(SigningKey{Algorithm: ML_DSA_44_Ed25519, Key: key}, &SignerOptions{EmbedJWK: true})
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSigned(obj.FullSerialize(), []SignatureAlgorithm{ML_DSA_44_Ed25519})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Signatures[0].Header.JSONWebKey == nil {
		t.Fatal("embedded JWK missing")
	}
	if _, err = parsed.Verify(parsed.Signatures[0].Header.JSONWebKey); err != nil {
		t.Fatalf("Verify with embedded composite JWK: %v", err)
	}
}

func TestCompositeAKPJWKRoundTrip(t *testing.T) {
	for _, alg := range []SignatureAlgorithm{ML_DSA_44_ES256, ML_DSA_65_Ed25519} {
		key := generateCompositeTestKey(t, alg)
		jwk := JSONWebKey{Key: key, Algorithm: string(alg), Use: "sig", KeyID: "composite"}
		marshaled, err := jwk.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var parsed JSONWebKey
		if err = parsed.UnmarshalJSON(marshaled); err != nil {
			t.Fatal(err)
		}
		parsedKey, ok := parsed.Key.(*CompositePrivateKey)
		if !ok {
			t.Fatalf("parsed key type = %T, want *CompositePrivateKey", parsed.Key)
		}
		if _, err = NewSigner(SigningKey{Algorithm: alg, Key: parsedKey}, nil); err != nil {
			t.Fatalf("parsed composite private key is not usable: %v", err)
		}

		public := parsed.Public()
		if !public.IsPublic() || !public.Valid() {
			t.Fatal("public composite JWK should be valid and public")
		}
		if _, err = public.Thumbprint(crypto.SHA256); err != nil {
			t.Fatalf("composite thumbprint failed: %v", err)
		}

		pubMarshaled, err := public.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var parsedPublic JSONWebKey
		if err = parsedPublic.UnmarshalJSON(pubMarshaled); err != nil {
			t.Fatal(err)
		}
		if _, ok = parsedPublic.Key.(*CompositePublicKey); !ok {
			t.Fatalf("parsed public key type = %T, want *CompositePublicKey", parsedPublic.Key)
		}
	}
}

func TestCompositeRejectsTamperedSignatures(t *testing.T) {
	key := generateCompositeTestKey(t, ML_DSA_65_Ed25519)
	signer, err := NewSigner(SigningKey{Algorithm: ML_DSA_65_Ed25519, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = obj.Verify(key.Public()); err != nil {
		t.Fatal(err)
	}

	tamperedMLDSA := *obj
	tamperedMLDSA.Signatures = append([]Signature(nil), obj.Signatures...)
	tamperedMLDSA.Signatures[0].Signature = append([]byte(nil), obj.Signatures[0].Signature...)
	tamperedMLDSA.Signatures[0].Signature[0] ^= 0x01
	if _, err = tamperedMLDSA.Verify(key.Public()); err == nil {
		t.Fatal("expected tampered ML-DSA component to fail")
	}

	params, _ := compositeParamsForAlgorithm(ML_DSA_65_Ed25519)
	tamperedTraditional := *obj
	tamperedTraditional.Signatures = append([]Signature(nil), obj.Signatures...)
	tamperedTraditional.Signatures[0].Signature = append([]byte(nil), obj.Signatures[0].Signature...)
	tamperedTraditional.Signatures[0].Signature[params.mldsaSignatureSize] ^= 0x01
	if _, err = tamperedTraditional.Verify(key.Public()); err == nil {
		t.Fatal("expected tampered traditional component to fail")
	}

	truncated := *obj
	truncated.Signatures = append([]Signature(nil), obj.Signatures...)
	truncated.Signatures[0].Signature = append([]byte(nil), obj.Signatures[0].Signature[:params.mldsaSignatureSize]...)
	if _, err = truncated.Verify(key.Public()); err == nil {
		t.Fatal("expected truncated composite signature to fail")
	}
}

func TestCompositeECDSASignatureUsesDER(t *testing.T) {
	key := generateCompositeTestKey(t, ML_DSA_44_ES256)
	signer, err := NewSigner(SigningKey{Algorithm: ML_DSA_44_ES256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := signer.Sign([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	params, _ := compositeParamsForAlgorithm(ML_DSA_44_ES256)
	ecdsaSig := obj.Signatures[0].Signature[params.mldsaSignatureSize:]
	var parsed struct {
		R, S *big.Int
	}
	rest, err := asn1.Unmarshal(ecdsaSig, &parsed)
	if err != nil {
		t.Fatalf("ECDSA component is not DER: %v", err)
	}
	if len(rest) != 0 || parsed.R == nil || parsed.S == nil {
		t.Fatal("ECDSA component DER did not decode to r/s")
	}
}

func TestCompositeRejectsWrongAlgorithmKeyPairing(t *testing.T) {
	key := generateCompositeTestKey(t, ML_DSA_44_ES256)
	if _, err := NewSigner(SigningKey{Algorithm: ML_DSA_65_ES256, Key: key}, nil); err == nil {
		t.Fatal("expected wrong composite algorithm/key pairing to fail")
	}
}

func generateCompositeTestKey(t *testing.T, alg SignatureAlgorithm) *CompositePrivateKey {
	t.Helper()

	params, ok := compositeParamsForAlgorithm(alg)
	if !ok {
		t.Fatalf("unsupported composite algorithm %s", alg)
	}
	mldsaParams, _, _, ok := mldsaParamsForAlgorithm(params.mldsaAlg)
	if !ok {
		t.Fatalf("unsupported ML-DSA algorithm %s", params.mldsaAlg)
	}
	mldsaKey, err := mldsa.GenerateKey(mldsaParams)
	if err != nil {
		t.Fatal(err)
	}

	key := &CompositePrivateKey{
		Algorithm: alg,
		MLDSA:     mldsaKey,
	}
	switch params.traditional {
	case compositeTraditionalECDSA:
		key.ECDSA, err = ecdsa.GenerateKey(params.ecdsaCurve, rand.Reader)
	case compositeTraditionalEd25519:
		_, key.Ed25519, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatalf("unsupported traditional component for %s", alg)
	}
	if err != nil {
		t.Fatal(err)
	}
	return key
}
