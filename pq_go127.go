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
	"crypto/elliptic"
	"crypto/mldsa"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

var compositePrefix = []byte("CompositeAlgorithmSignatures2025")

type mldsaSigner struct {
	privateKey *mldsa.PrivateKey
}

type mldsaVerifier struct {
	publicKey *mldsa.PublicKey
}

// CompositePublicKey is a public key for draft-ietf-jose-pq-composite-sigs.
type CompositePublicKey struct {
	Algorithm SignatureAlgorithm
	MLDSA     *mldsa.PublicKey
	ECDSA     *ecdsa.PublicKey
	Ed25519   ed25519.PublicKey
}

// CompositePrivateKey is a private key for draft-ietf-jose-pq-composite-sigs.
type CompositePrivateKey struct {
	Algorithm SignatureAlgorithm
	MLDSA     *mldsa.PrivateKey
	ECDSA     *ecdsa.PrivateKey
	Ed25519   ed25519.PrivateKey
}

// Public returns the corresponding CompositePublicKey.
func (k *CompositePrivateKey) Public() crypto.PublicKey {
	if k == nil || k.MLDSA == nil {
		return nil
	}

	ret := &CompositePublicKey{
		Algorithm: k.Algorithm,
		MLDSA:     k.MLDSA.PublicKey(),
	}
	if k.ECDSA != nil {
		ret.ECDSA = &k.ECDSA.PublicKey
	}
	if k.Ed25519 != nil {
		ret.Ed25519 = k.Ed25519.Public().(ed25519.PublicKey)
	}
	return ret
}

type compositeSigner struct {
	privateKey *CompositePrivateKey
}

type compositeVerifier struct {
	publicKey *CompositePublicKey
}

type compositeTraditional int

const (
	compositeTraditionalECDSA compositeTraditional = iota
	compositeTraditionalEd25519
)

type compositeParams struct {
	alg                      SignatureAlgorithm
	mldsaAlg                 SignatureAlgorithm
	mldsaPublicKeySize       int
	mldsaSignatureSize       int
	label                    string
	preHash                  crypto.Hash
	traditional              compositeTraditional
	ecdsaCurve               elliptic.Curve
	ecdsaSignatureHash       crypto.Hash
	traditionalPublicKeySize int
	traditionalPrivKeySize   int
	traditionalSigSize       int
}

func makePQJWSRecipient(alg SignatureAlgorithm, signingKey interface{}) (recipientSigInfo, error) {
	switch signingKey := signingKey.(type) {
	case *mldsa.PrivateKey:
		return newMLDSASigner(alg, signingKey)
	case *CompositePrivateKey:
		return newCompositeSigner(alg, signingKey)
	case CompositePrivateKey:
		return newCompositeSigner(alg, &signingKey)
	case JSONWebKey:
		return newJWKSigner(alg, signingKey)
	case *JSONWebKey:
		return newJWKSigner(alg, *signingKey)
	case OpaqueSigner:
		return newOpaqueSigner(alg, signingKey)
	default:
		return recipientSigInfo{}, ErrUnsupportedKeyType
	}
}

func newPQVerifier(verificationKey interface{}) (payloadVerifier, bool, error) {
	switch verificationKey := verificationKey.(type) {
	case *mldsa.PublicKey:
		return &mldsaVerifier{publicKey: verificationKey}, true, nil
	case *CompositePublicKey:
		return &compositeVerifier{publicKey: verificationKey}, true, nil
	case CompositePublicKey:
		return &compositeVerifier{publicKey: &verificationKey}, true, nil
	default:
		return nil, false, nil
	}
}

func newMLDSASigner(sigAlg SignatureAlgorithm, privateKey *mldsa.PrivateKey) (recipientSigInfo, error) {
	if _, _, _, ok := mldsaParamsForAlgorithm(sigAlg); !ok {
		return recipientSigInfo{}, ErrUnsupportedAlgorithm
	}
	if privateKey == nil {
		return recipientSigInfo{}, errors.New("invalid private key")
	}
	if err := validateMLDSAParams(sigAlg, privateKey.PublicKey().Parameters()); err != nil {
		return recipientSigInfo{}, err
	}

	return recipientSigInfo{
		sigAlg: sigAlg,
		publicKey: staticPublicKey(&JSONWebKey{
			Key:       privateKey.PublicKey(),
			Algorithm: string(sigAlg),
		}),
		signer: &mldsaSigner{privateKey: privateKey},
	}, nil
}

func (ctx *mldsaSigner) signPayload(payload []byte, alg SignatureAlgorithm) (Signature, error) {
	if err := validateMLDSAParams(alg, ctx.privateKey.PublicKey().Parameters()); err != nil {
		return Signature{}, err
	}

	sig, err := ctx.privateKey.Sign(randReader, payload, &mldsa.Options{})
	if err != nil {
		return Signature{}, err
	}
	return Signature{Signature: sig, protected: &rawHeader{}}, nil
}

func (ctx *mldsaVerifier) verifyPayload(payload []byte, signature []byte, alg SignatureAlgorithm) error {
	if err := validateMLDSAParams(alg, ctx.publicKey.Parameters()); err != nil {
		return err
	}
	if err := mldsa.Verify(ctx.publicKey, payload, signature, &mldsa.Options{}); err != nil {
		return fmt.Errorf("go-jose/go-jose: mldsa signature failed to verify: %w", err)
	}
	return nil
}

func newCompositeSigner(sigAlg SignatureAlgorithm, privateKey *CompositePrivateKey) (recipientSigInfo, error) {
	params, err := validateCompositePrivateKey(sigAlg, privateKey)
	if err != nil {
		return recipientSigInfo{}, err
	}

	return recipientSigInfo{
		sigAlg: sigAlg,
		publicKey: staticPublicKey(&JSONWebKey{
			Key:       privateKey.Public().(*CompositePublicKey),
			Algorithm: string(params.alg),
		}),
		signer: &compositeSigner{privateKey: privateKey},
	}, nil
}

func (ctx *compositeSigner) signPayload(payload []byte, alg SignatureAlgorithm) (Signature, error) {
	params, err := validateCompositePrivateKey(alg, ctx.privateKey)
	if err != nil {
		return Signature{}, err
	}

	representative, err := compositeMessageRepresentative(params, payload)
	if err != nil {
		return Signature{}, err
	}

	mldsaSig, err := ctx.privateKey.MLDSA.Sign(randReader, representative, &mldsa.Options{Context: params.label})
	if err != nil {
		return Signature{}, err
	}

	var traditionalSig []byte
	switch params.traditional {
	case compositeTraditionalECDSA:
		hasher := params.ecdsaSignatureHash.New()
		_, _ = hasher.Write(representative)
		traditionalSig, err = ecdsa.SignASN1(randReader, ctx.privateKey.ECDSA, hasher.Sum(nil))
	case compositeTraditionalEd25519:
		traditionalSig, err = ctx.privateKey.Ed25519.Sign(randReader, representative, crypto.Hash(0))
	default:
		return Signature{}, ErrUnsupportedAlgorithm
	}
	if err != nil {
		return Signature{}, err
	}

	signature := make([]byte, 0, len(mldsaSig)+len(traditionalSig))
	signature = append(signature, mldsaSig...)
	signature = append(signature, traditionalSig...)
	return Signature{Signature: signature, protected: &rawHeader{}}, nil
}

func (ctx *compositeVerifier) verifyPayload(payload []byte, signature []byte, alg SignatureAlgorithm) error {
	params, err := validateCompositePublicKey(alg, ctx.publicKey)
	if err != nil {
		return err
	}
	if len(signature) < params.mldsaSignatureSize {
		return fmt.Errorf("go-jose/go-jose: invalid signature size, have %d bytes, wanted at least %d", len(signature), params.mldsaSignatureSize)
	}

	mldsaSig := signature[:params.mldsaSignatureSize]
	traditionalSig := signature[params.mldsaSignatureSize:]
	if params.traditionalSigSize > 0 && len(traditionalSig) != params.traditionalSigSize {
		return fmt.Errorf("go-jose/go-jose: invalid signature size, have %d byte traditional signature, wanted %d", len(traditionalSig), params.traditionalSigSize)
	}
	if len(traditionalSig) == 0 {
		return errors.New("go-jose/go-jose: invalid composite signature, missing traditional signature")
	}

	representative, err := compositeMessageRepresentative(params, payload)
	if err != nil {
		return err
	}

	if err := mldsa.Verify(ctx.publicKey.MLDSA, representative, mldsaSig, &mldsa.Options{Context: params.label}); err != nil {
		return fmt.Errorf("go-jose/go-jose: composite mldsa signature failed to verify: %w", err)
	}

	var ok bool
	switch params.traditional {
	case compositeTraditionalECDSA:
		hasher := params.ecdsaSignatureHash.New()
		_, _ = hasher.Write(representative)
		ok = ecdsa.VerifyASN1(ctx.publicKey.ECDSA, hasher.Sum(nil), traditionalSig)
	case compositeTraditionalEd25519:
		ok = ed25519.Verify(ctx.publicKey.Ed25519, representative, traditionalSig)
	default:
		return ErrUnsupportedAlgorithm
	}
	if !ok {
		return errors.New("go-jose/go-jose: composite traditional signature failed to verify")
	}
	return nil
}

func marshalAKPKey(k JSONWebKey) (*rawJSONWebKey, bool, error) {
	switch key := k.Key.(type) {
	case *mldsa.PublicKey:
		if key == nil {
			return nil, true, errors.New("invalid public key")
		}
		alg, err := normalizeMLDSAAlgorithm(k.Algorithm, key.Parameters())
		if err != nil {
			return nil, true, err
		}
		return fromAKPPublicKey(alg, key.Bytes()), true, nil
	case *mldsa.PrivateKey:
		if key == nil {
			return nil, true, errors.New("invalid private key")
		}
		alg, err := normalizeMLDSAAlgorithm(k.Algorithm, key.PublicKey().Parameters())
		if err != nil {
			return nil, true, err
		}
		raw := fromAKPPublicKey(alg, key.PublicKey().Bytes())
		raw.Priv = newBuffer(key.Bytes())
		return raw, true, nil
	case *CompositePublicKey:
		raw, err := fromCompositePublicKey(k.Algorithm, key)
		return raw, true, err
	case CompositePublicKey:
		raw, err := fromCompositePublicKey(k.Algorithm, &key)
		return raw, true, err
	case *CompositePrivateKey:
		raw, err := fromCompositePrivateKey(k.Algorithm, key)
		return raw, true, err
	case CompositePrivateKey:
		raw, err := fromCompositePrivateKey(k.Algorithm, &key)
		return raw, true, err
	default:
		return nil, false, nil
	}
}

func parseAKPKey(raw rawJSONWebKey) (interface{}, interface{}, error) {
	if raw.Alg == "" {
		return nil, nil, errors.New("go-jose/go-jose: invalid AKP key, missing alg value")
	}
	if raw.Pub == nil {
		return nil, nil, errors.New("go-jose/go-jose: invalid AKP key, missing pub value")
	}

	alg := SignatureAlgorithm(raw.Alg)
	if isMLDSAAlgorithm(alg) {
		params, _, _, ok := mldsaParamsForAlgorithm(alg)
		if !ok {
			return nil, nil, ErrUnsupportedAlgorithm
		}
		publicKey, err := mldsa.NewPublicKey(params, raw.Pub.bytes())
		if err != nil {
			return nil, nil, err
		}
		if raw.Priv == nil {
			return publicKey, publicKey, nil
		}
		privateKey, err := mldsa.NewPrivateKey(params, raw.Priv.bytes())
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(privateKey.PublicKey().Bytes(), publicKey.Bytes()) {
			return nil, nil, errors.New("go-jose/go-jose: invalid AKP key, pub does not match priv")
		}
		return privateKey, privateKey.PublicKey(), nil
	}

	if isCompositeAlgorithm(alg) {
		publicKey, err := parseCompositePublicKey(alg, raw.Pub.bytes())
		if err != nil {
			return nil, nil, err
		}
		if raw.Priv == nil {
			return publicKey, publicKey, nil
		}
		privateKey, err := parseCompositePrivateKey(alg, raw.Priv.bytes())
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(mustCompositePublicBytes(publicKey), mustCompositePublicBytes(privateKey.Public().(*CompositePublicKey))) {
			return nil, nil, errors.New("go-jose/go-jose: invalid AKP key, pub does not match priv")
		}
		return privateKey, privateKey.Public(), nil
	}

	return nil, nil, ErrUnsupportedAlgorithm
}

func akpThumbprint(k *JSONWebKey) (string, bool, error) {
	switch key := k.Key.(type) {
	case *mldsa.PublicKey:
		if key == nil {
			return "", true, errors.New("invalid public key")
		}
		alg, err := normalizeMLDSAAlgorithm(k.Algorithm, key.Parameters())
		if err != nil {
			return "", true, err
		}
		input, err := akpThumbprintInput(string(alg), key.Bytes())
		return input, true, err
	case *mldsa.PrivateKey:
		if key == nil {
			return "", true, errors.New("invalid private key")
		}
		alg, err := normalizeMLDSAAlgorithm(k.Algorithm, key.PublicKey().Parameters())
		if err != nil {
			return "", true, err
		}
		input, err := akpThumbprintInput(string(alg), key.PublicKey().Bytes())
		return input, true, err
	case *CompositePublicKey:
		alg, pub, err := compositeAKPPublic(k.Algorithm, key)
		if err != nil {
			return "", true, err
		}
		input, err := akpThumbprintInput(string(alg), pub)
		return input, true, err
	case CompositePublicKey:
		alg, pub, err := compositeAKPPublic(k.Algorithm, &key)
		if err != nil {
			return "", true, err
		}
		input, err := akpThumbprintInput(string(alg), pub)
		return input, true, err
	case *CompositePrivateKey:
		publicKey, ok := key.Public().(*CompositePublicKey)
		if !ok {
			return "", true, errors.New("invalid private key")
		}
		alg, pub, err := compositeAKPPublic(k.Algorithm, publicKey)
		if err != nil {
			return "", true, err
		}
		input, err := akpThumbprintInput(string(alg), pub)
		return input, true, err
	case CompositePrivateKey:
		publicKey, ok := key.Public().(*CompositePublicKey)
		if !ok {
			return "", true, errors.New("invalid private key")
		}
		alg, pub, err := compositeAKPPublic(k.Algorithm, publicKey)
		if err != nil {
			return "", true, err
		}
		input, err := akpThumbprintInput(string(alg), pub)
		return input, true, err
	default:
		return "", false, nil
	}
}

func akpIsPublic(key interface{}) bool {
	switch key.(type) {
	case *mldsa.PublicKey, *CompositePublicKey, CompositePublicKey:
		return true
	default:
		return false
	}
}

func akpPublic(k JSONWebKey) (JSONWebKey, bool) {
	ret := k
	switch key := k.Key.(type) {
	case *mldsa.PrivateKey:
		ret.Key = key.PublicKey()
	case *CompositePrivateKey:
		ret.Key = key.Public()
	case CompositePrivateKey:
		ret.Key = key.Public()
	default:
		return JSONWebKey{}, false
	}
	return ret, true
}

func akpValid(key interface{}) bool {
	switch key := key.(type) {
	case *mldsa.PublicKey:
		if key == nil {
			return false
		}
		return validateMLDSAParams(mldsaAlgorithmForParams(key.Parameters()), key.Parameters()) == nil
	case *mldsa.PrivateKey:
		if key == nil {
			return false
		}
		return validateMLDSAParams(mldsaAlgorithmForParams(key.PublicKey().Parameters()), key.PublicKey().Parameters()) == nil
	case *CompositePublicKey:
		alg, err := inferCompositePublicKeyAlgorithm(key)
		if err != nil {
			return false
		}
		_, err = validateCompositePublicKey(alg, key)
		return err == nil
	case CompositePublicKey:
		alg, err := inferCompositePublicKeyAlgorithm(&key)
		if err != nil {
			return false
		}
		_, err = validateCompositePublicKey(alg, &key)
		return err == nil
	case *CompositePrivateKey:
		alg, err := inferCompositePrivateKeyAlgorithm(key)
		if err != nil {
			return false
		}
		_, err = validateCompositePrivateKey(alg, key)
		return err == nil
	case CompositePrivateKey:
		alg, err := inferCompositePrivateKeyAlgorithm(&key)
		if err != nil {
			return false
		}
		_, err = validateCompositePrivateKey(alg, &key)
		return err == nil
	default:
		return false
	}
}

func mldsaParamsForAlgorithm(alg SignatureAlgorithm) (mldsa.Parameters, int, int, bool) {
	switch alg {
	case ML_DSA_44:
		return mldsa.MLDSA44(), mldsa.MLDSA44PublicKeySize, mldsa.MLDSA44SignatureSize, true
	case ML_DSA_65:
		return mldsa.MLDSA65(), mldsa.MLDSA65PublicKeySize, mldsa.MLDSA65SignatureSize, true
	case ML_DSA_87:
		return mldsa.MLDSA87(), mldsa.MLDSA87PublicKeySize, mldsa.MLDSA87SignatureSize, true
	default:
		return mldsa.Parameters{}, 0, 0, false
	}
}

func mldsaAlgorithmForParams(params mldsa.Parameters) SignatureAlgorithm {
	if params == mldsa.MLDSA44() {
		return ML_DSA_44
	}
	if params == mldsa.MLDSA65() {
		return ML_DSA_65
	}
	if params == mldsa.MLDSA87() {
		return ML_DSA_87
	}
	return ""
}

func normalizeMLDSAAlgorithm(alg string, params mldsa.Parameters) (SignatureAlgorithm, error) {
	inferred := mldsaAlgorithmForParams(params)
	if inferred == "" {
		return "", ErrUnsupportedAlgorithm
	}
	if alg != "" && SignatureAlgorithm(alg) != inferred {
		return "", fmt.Errorf("go-jose/go-jose: alg %s does not match key parameters %s", alg, params)
	}
	return inferred, nil
}

func validateMLDSAParams(alg SignatureAlgorithm, params mldsa.Parameters) error {
	expected, _, _, ok := mldsaParamsForAlgorithm(alg)
	if !ok {
		return ErrUnsupportedAlgorithm
	}
	if params != expected {
		return fmt.Errorf("go-jose/go-jose: alg %s does not match key parameters %s", alg, params)
	}
	return nil
}

func compositeParamsForAlgorithm(alg SignatureAlgorithm) (*compositeParams, bool) {
	switch alg {
	case ML_DSA_44_ES256:
		return &compositeParams{
			alg:                      alg,
			mldsaAlg:                 ML_DSA_44,
			mldsaPublicKeySize:       mldsa.MLDSA44PublicKeySize,
			mldsaSignatureSize:       mldsa.MLDSA44SignatureSize,
			label:                    "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
			preHash:                  crypto.SHA256,
			traditional:              compositeTraditionalECDSA,
			ecdsaCurve:               elliptic.P256(),
			ecdsaSignatureHash:       crypto.SHA256,
			traditionalPublicKeySize: 1 + 2*curveSize(elliptic.P256()),
		}, true
	case ML_DSA_65_ES256:
		return &compositeParams{
			alg:                      alg,
			mldsaAlg:                 ML_DSA_65,
			mldsaPublicKeySize:       mldsa.MLDSA65PublicKeySize,
			mldsaSignatureSize:       mldsa.MLDSA65SignatureSize,
			label:                    "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
			preHash:                  crypto.SHA512,
			traditional:              compositeTraditionalECDSA,
			ecdsaCurve:               elliptic.P256(),
			ecdsaSignatureHash:       crypto.SHA256,
			traditionalPublicKeySize: 1 + 2*curveSize(elliptic.P256()),
		}, true
	case ML_DSA_87_ES384:
		return &compositeParams{
			alg:                      alg,
			mldsaAlg:                 ML_DSA_87,
			mldsaPublicKeySize:       mldsa.MLDSA87PublicKeySize,
			mldsaSignatureSize:       mldsa.MLDSA87SignatureSize,
			label:                    "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
			preHash:                  crypto.SHA512,
			traditional:              compositeTraditionalECDSA,
			ecdsaCurve:               elliptic.P384(),
			ecdsaSignatureHash:       crypto.SHA384,
			traditionalPublicKeySize: 1 + 2*curveSize(elliptic.P384()),
		}, true
	case ML_DSA_44_Ed25519:
		return &compositeParams{
			alg:                      alg,
			mldsaAlg:                 ML_DSA_44,
			mldsaPublicKeySize:       mldsa.MLDSA44PublicKeySize,
			mldsaSignatureSize:       mldsa.MLDSA44SignatureSize,
			label:                    "COMPSIG-MLDSA44-Ed25519-SHA512",
			preHash:                  crypto.SHA512,
			traditional:              compositeTraditionalEd25519,
			traditionalPublicKeySize: ed25519.PublicKeySize,
			traditionalPrivKeySize:   ed25519.SeedSize,
			traditionalSigSize:       ed25519.SignatureSize,
		}, true
	case ML_DSA_65_Ed25519:
		return &compositeParams{
			alg:                      alg,
			mldsaAlg:                 ML_DSA_65,
			mldsaPublicKeySize:       mldsa.MLDSA65PublicKeySize,
			mldsaSignatureSize:       mldsa.MLDSA65SignatureSize,
			label:                    "COMPSIG-MLDSA65-Ed25519-SHA512",
			preHash:                  crypto.SHA512,
			traditional:              compositeTraditionalEd25519,
			traditionalPublicKeySize: ed25519.PublicKeySize,
			traditionalPrivKeySize:   ed25519.SeedSize,
			traditionalSigSize:       ed25519.SignatureSize,
		}, true
	default:
		return nil, false
	}
}

func compositeMessageRepresentative(params *compositeParams, payload []byte) ([]byte, error) {
	if !params.preHash.Available() {
		return nil, fmt.Errorf("go-jose/go-jose: hash function unavailable for %s", params.alg)
	}
	hasher := params.preHash.New()
	_, _ = hasher.Write(payload)

	representative := make([]byte, 0, len(compositePrefix)+len(params.label)+1+hasher.Size())
	representative = append(representative, compositePrefix...)
	representative = append(representative, params.label...)
	representative = append(representative, 0)
	representative = append(representative, hasher.Sum(nil)...)

	encoded := base64.RawURLEncoding.EncodeToString(representative)
	return []byte(encoded), nil
}

func validateCompositePublicKey(alg SignatureAlgorithm, key *CompositePublicKey) (*compositeParams, error) {
	params, ok := compositeParamsForAlgorithm(alg)
	if !ok {
		return nil, ErrUnsupportedAlgorithm
	}
	if key == nil || key.MLDSA == nil {
		return nil, errors.New("invalid public key")
	}
	if key.Algorithm != "" && key.Algorithm != alg {
		return nil, fmt.Errorf("go-jose/go-jose: alg %s does not match composite key algorithm %s", alg, key.Algorithm)
	}
	if err := validateMLDSAParams(params.mldsaAlg, key.MLDSA.Parameters()); err != nil {
		return nil, err
	}

	switch params.traditional {
	case compositeTraditionalECDSA:
		if key.ECDSA == nil || key.Ed25519 != nil {
			return nil, errors.New("invalid public key")
		}
		if key.ECDSA.Curve != params.ecdsaCurve || key.ECDSA.X == nil || key.ECDSA.Y == nil || !key.ECDSA.Curve.IsOnCurve(key.ECDSA.X, key.ECDSA.Y) {
			return nil, errors.New("invalid public key")
		}
	case compositeTraditionalEd25519:
		if key.ECDSA != nil || len(key.Ed25519) != ed25519.PublicKeySize {
			return nil, errors.New("invalid public key")
		}
	default:
		return nil, ErrUnsupportedAlgorithm
	}
	return params, nil
}

func validateCompositePrivateKey(alg SignatureAlgorithm, key *CompositePrivateKey) (*compositeParams, error) {
	params, ok := compositeParamsForAlgorithm(alg)
	if !ok {
		return nil, ErrUnsupportedAlgorithm
	}
	if key == nil || key.MLDSA == nil {
		return nil, errors.New("invalid private key")
	}
	if key.Algorithm != "" && key.Algorithm != alg {
		return nil, fmt.Errorf("go-jose/go-jose: alg %s does not match composite key algorithm %s", alg, key.Algorithm)
	}
	if err := validateMLDSAParams(params.mldsaAlg, key.MLDSA.PublicKey().Parameters()); err != nil {
		return nil, err
	}

	switch params.traditional {
	case compositeTraditionalECDSA:
		if key.ECDSA == nil || key.Ed25519 != nil {
			return nil, errors.New("invalid private key")
		}
		if key.ECDSA.Curve != params.ecdsaCurve || key.ECDSA.X == nil || key.ECDSA.Y == nil || key.ECDSA.D == nil || !key.ECDSA.Curve.IsOnCurve(key.ECDSA.X, key.ECDSA.Y) {
			return nil, errors.New("invalid private key")
		}
	case compositeTraditionalEd25519:
		if key.ECDSA != nil || len(key.Ed25519) != ed25519.PrivateKeySize {
			return nil, errors.New("invalid private key")
		}
	default:
		return nil, ErrUnsupportedAlgorithm
	}
	return params, nil
}

func fromAKPPublicKey(alg SignatureAlgorithm, pub []byte) *rawJSONWebKey {
	return &rawJSONWebKey{
		Kty: "AKP",
		Alg: string(alg),
		Pub: newBuffer(pub),
	}
}

func fromCompositePublicKey(alg string, key *CompositePublicKey) (*rawJSONWebKey, error) {
	resolvedAlg, pub, err := compositeAKPPublic(alg, key)
	if err != nil {
		return nil, err
	}
	return fromAKPPublicKey(resolvedAlg, pub), nil
}

func fromCompositePrivateKey(alg string, key *CompositePrivateKey) (*rawJSONWebKey, error) {
	if key == nil {
		return nil, errors.New("invalid private key")
	}
	publicKey, ok := key.Public().(*CompositePublicKey)
	if !ok {
		return nil, errors.New("invalid private key")
	}
	resolvedAlg, pub, err := compositeAKPPublic(alg, publicKey)
	if err != nil {
		return nil, err
	}
	priv, err := compositePrivateBytes(resolvedAlg, key)
	if err != nil {
		return nil, err
	}
	raw := fromAKPPublicKey(resolvedAlg, pub)
	raw.Priv = newBuffer(priv)
	return raw, nil
}

func compositeAKPPublic(alg string, key *CompositePublicKey) (SignatureAlgorithm, []byte, error) {
	resolvedAlg, err := normalizeCompositePublicKeyAlgorithm(alg, key)
	if err != nil {
		return "", nil, err
	}
	if _, err := validateCompositePublicKey(resolvedAlg, key); err != nil {
		return "", nil, err
	}
	return resolvedAlg, mustCompositePublicBytes(key), nil
}

func mustCompositePublicBytes(key *CompositePublicKey) []byte {
	pub := key.MLDSA.Bytes()
	switch {
	case key.ECDSA != nil:
		pub = append(pub, elliptic.Marshal(key.ECDSA.Curve, key.ECDSA.X, key.ECDSA.Y)...)
	case key.Ed25519 != nil:
		pub = append(pub, key.Ed25519...)
	}
	return pub
}

func compositePrivateBytes(alg SignatureAlgorithm, key *CompositePrivateKey) ([]byte, error) {
	params, err := validateCompositePrivateKey(alg, key)
	if err != nil {
		return nil, err
	}

	priv := key.MLDSA.Bytes()
	switch params.traditional {
	case compositeTraditionalECDSA:
		ecPriv, err := marshalCompositeECPrivateKey(key.ECDSA)
		if err != nil {
			return nil, err
		}
		priv = append(priv, ecPriv...)
	case compositeTraditionalEd25519:
		priv = append(priv, key.Ed25519.Seed()...)
	default:
		return nil, ErrUnsupportedAlgorithm
	}
	return priv, nil
}

func parseCompositePublicKey(alg SignatureAlgorithm, encoded []byte) (*CompositePublicKey, error) {
	params, ok := compositeParamsForAlgorithm(alg)
	if !ok {
		return nil, ErrUnsupportedAlgorithm
	}
	if len(encoded) != params.mldsaPublicKeySize+params.traditionalPublicKeySize {
		return nil, fmt.Errorf("go-jose/go-jose: invalid AKP key, pub has %d bytes, want %d", len(encoded), params.mldsaPublicKeySize+params.traditionalPublicKeySize)
	}

	mldsaParams, _, _, _ := mldsaParamsForAlgorithm(params.mldsaAlg)
	mldsaPub, err := mldsa.NewPublicKey(mldsaParams, encoded[:params.mldsaPublicKeySize])
	if err != nil {
		return nil, err
	}
	traditionalPub := encoded[params.mldsaPublicKeySize:]

	key := &CompositePublicKey{
		Algorithm: alg,
		MLDSA:     mldsaPub,
	}
	switch params.traditional {
	case compositeTraditionalECDSA:
		x, y := elliptic.Unmarshal(params.ecdsaCurve, traditionalPub)
		if x == nil || y == nil {
			return nil, errors.New("go-jose/go-jose: invalid AKP key, invalid ECDSA public key")
		}
		key.ECDSA = &ecdsa.PublicKey{Curve: params.ecdsaCurve, X: x, Y: y}
	case compositeTraditionalEd25519:
		key.Ed25519 = ed25519.PublicKey(append([]byte(nil), traditionalPub...))
	default:
		return nil, ErrUnsupportedAlgorithm
	}
	return key, nil
}

func parseCompositePrivateKey(alg SignatureAlgorithm, encoded []byte) (*CompositePrivateKey, error) {
	params, ok := compositeParamsForAlgorithm(alg)
	if !ok {
		return nil, ErrUnsupportedAlgorithm
	}
	if len(encoded) < mldsa.PrivateKeySize {
		return nil, fmt.Errorf("go-jose/go-jose: invalid AKP key, priv has %d bytes, want at least %d", len(encoded), mldsa.PrivateKeySize)
	}
	mldsaParams, _, _, _ := mldsaParamsForAlgorithm(params.mldsaAlg)
	mldsaPriv, err := mldsa.NewPrivateKey(mldsaParams, encoded[:mldsa.PrivateKeySize])
	if err != nil {
		return nil, err
	}
	traditionalPriv := encoded[mldsa.PrivateKeySize:]

	key := &CompositePrivateKey{
		Algorithm: alg,
		MLDSA:     mldsaPriv,
	}
	switch params.traditional {
	case compositeTraditionalECDSA:
		ecPriv, err := parseCompositeECPrivateKey(params.ecdsaCurve, traditionalPriv)
		if err != nil {
			return nil, err
		}
		key.ECDSA = ecPriv
	case compositeTraditionalEd25519:
		if len(traditionalPriv) != ed25519.SeedSize {
			return nil, fmt.Errorf("go-jose/go-jose: invalid AKP key, Ed25519 priv has %d bytes, want %d", len(traditionalPriv), ed25519.SeedSize)
		}
		key.Ed25519 = ed25519.NewKeyFromSeed(traditionalPriv)
	default:
		return nil, ErrUnsupportedAlgorithm
	}
	return key, nil
}

func normalizeCompositePublicKeyAlgorithm(alg string, key *CompositePublicKey) (SignatureAlgorithm, error) {
	inferred, err := inferCompositePublicKeyAlgorithm(key)
	if err != nil {
		return "", err
	}
	if alg != "" && SignatureAlgorithm(alg) != inferred {
		return "", fmt.Errorf("go-jose/go-jose: alg %s does not match composite key algorithm %s", alg, inferred)
	}
	return inferred, nil
}

func inferCompositePublicKeyAlgorithm(key *CompositePublicKey) (SignatureAlgorithm, error) {
	if key == nil || key.MLDSA == nil {
		return "", errors.New("invalid public key")
	}
	if key.Algorithm != "" {
		return key.Algorithm, nil
	}
	mldsaAlg := mldsaAlgorithmForParams(key.MLDSA.Parameters())
	switch {
	case key.ECDSA != nil && key.ECDSA.Curve == elliptic.P256() && mldsaAlg == ML_DSA_44:
		return ML_DSA_44_ES256, nil
	case key.ECDSA != nil && key.ECDSA.Curve == elliptic.P256() && mldsaAlg == ML_DSA_65:
		return ML_DSA_65_ES256, nil
	case key.ECDSA != nil && key.ECDSA.Curve == elliptic.P384() && mldsaAlg == ML_DSA_87:
		return ML_DSA_87_ES384, nil
	case len(key.Ed25519) == ed25519.PublicKeySize && mldsaAlg == ML_DSA_44:
		return ML_DSA_44_Ed25519, nil
	case len(key.Ed25519) == ed25519.PublicKeySize && mldsaAlg == ML_DSA_65:
		return ML_DSA_65_Ed25519, nil
	default:
		return "", ErrUnsupportedAlgorithm
	}
}

func inferCompositePrivateKeyAlgorithm(key *CompositePrivateKey) (SignatureAlgorithm, error) {
	if key == nil || key.MLDSA == nil {
		return "", errors.New("invalid private key")
	}
	if key.Algorithm != "" {
		return key.Algorithm, nil
	}
	publicKey, ok := key.Public().(*CompositePublicKey)
	if !ok {
		return "", errors.New("invalid private key")
	}
	return inferCompositePublicKeyAlgorithm(publicKey)
}

type ecPrivateKey struct {
	Version    int
	PrivateKey []byte
	NamedCurve asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
}

var (
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
)

func marshalCompositeECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	if key == nil || key.D == nil {
		return nil, errors.New("invalid private key")
	}
	oid, err := oidFromNamedCurve(key.Curve)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(ecPrivateKey{
		Version:    1,
		PrivateKey: newFixedSizeBuffer(key.D.Bytes(), dSize(key.Curve)).bytes(),
		NamedCurve: oid,
	})
}

func parseCompositeECPrivateKey(curve elliptic.Curve, der []byte) (*ecdsa.PrivateKey, error) {
	var parsed ecPrivateKey
	rest, err := asn1.Unmarshal(der, &parsed)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("go-jose/go-jose: invalid EC private key, trailing data")
	}
	if parsed.Version != 1 {
		return nil, errors.New("go-jose/go-jose: invalid EC private key version")
	}
	if dSize(curve) != len(parsed.PrivateKey) {
		return nil, fmt.Errorf("go-jose/go-jose: invalid EC private key, wrong length for d")
	}
	expectedOID, err := oidFromNamedCurve(curve)
	if err != nil {
		return nil, err
	}
	if !parsed.NamedCurve.Equal(expectedOID) {
		return nil, errors.New("go-jose/go-jose: invalid EC private key, wrong named curve")
	}

	x, y := curve.ScalarBaseMult(parsed.PrivateKey)
	if x == nil || y == nil || !curve.IsOnCurve(x, y) {
		return nil, errors.New("go-jose/go-jose: invalid EC private key")
	}
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         new(big.Int).SetBytes(parsed.PrivateKey),
	}, nil
}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, error) {
	switch curve {
	case elliptic.P256():
		return oidNamedCurveP256, nil
	case elliptic.P384():
		return oidNamedCurveP384, nil
	default:
		return nil, ErrUnsupportedEllipticCurve
	}
}
