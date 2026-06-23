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

package jose

import (
	"crypto/aes"
	"crypto/mlkem"
	"errors"
	"fmt"

	josecipher "github.com/go-jose/go-jose/v4/cipher"
)

type mlkemEncapsulationKey interface {
	Bytes() []byte
	Encapsulate() (sharedKey, ciphertext []byte)
}

type mlkemKeyGenerator struct {
	size      int
	algID     string
	publicKey mlkemEncapsulationKey
}

type mlkemEncrypter struct {
	publicKey mlkemEncapsulationKey
}

type mlkemDecrypter struct {
	privateKey interface{}
}

func newMLKEMRecipient(keyAlg KeyAlgorithm, publicKey interface{}) (recipientKeyInfo, error) {
	key, err := mlkemEncapsulationKeyForAlgorithm(keyAlg, publicKey)
	if err != nil {
		return recipientKeyInfo{}, err
	}

	return recipientKeyInfo{
		keyAlg: keyAlg,
		keyEncrypter: &mlkemEncrypter{
			publicKey: key,
		},
	}, nil
}

func (ctx mlkemKeyGenerator) keySize() int {
	return ctx.size
}

func (ctx mlkemKeyGenerator) genKey() ([]byte, rawHeader, error) {
	if ctx.publicKey == nil {
		return nil, nil, errors.New("go-jose/go-jose: invalid public key")
	}

	sharedKey, ciphertext := ctx.publicKey.Encapsulate()
	derivedKey := josecipher.DeriveMLKEM(ctx.algID, sharedKey, nil, ctx.size)

	headers := rawHeader{}
	if err := headers.set(headerEK, newBuffer(ciphertext)); err != nil {
		return nil, nil, err
	}

	return derivedKey, headers, nil
}

func (ctx mlkemEncrypter) encryptKey(cek []byte, alg KeyAlgorithm) (recipientInfo, error) {
	switch alg {
	case ML_KEM_768, ML_KEM_1024:
		return recipientInfo{
			header: &rawHeader{},
		}, nil
	case ML_KEM_768_A192KW, ML_KEM_1024_A256KW:
	default:
		return recipientInfo{}, ErrUnsupportedAlgorithm
	}

	if ctx.publicKey == nil {
		return recipientInfo{}, errors.New("go-jose/go-jose: invalid public key")
	}

	kekSize, err := mlkemKeyWrapSize(alg)
	if err != nil {
		return recipientInfo{}, err
	}
	sharedKey, ciphertext := ctx.publicKey.Encapsulate()
	kek := josecipher.DeriveMLKEM(string(alg), sharedKey, nil, kekSize)

	block, err := aes.NewCipher(kek)
	if err != nil {
		return recipientInfo{}, err
	}
	encryptedKey, err := josecipher.KeyWrap(block, cek)
	if err != nil {
		return recipientInfo{}, err
	}

	header := &rawHeader{}
	if err := header.set(headerEK, newBuffer(ciphertext)); err != nil {
		return recipientInfo{}, err
	}

	return recipientInfo{
		header:       header,
		encryptedKey: encryptedKey,
	}, nil
}

func (ctx mlkemDecrypter) decryptKey(headers rawHeader, recipient *recipientInfo, generator keyGenerator) ([]byte, error) {
	if recipient == nil {
		return nil, errors.New("go-jose/go-jose: missing recipient")
	}
	if headers.isSet(headerAPU) {
		return nil, errors.New("go-jose/go-jose: apu header is not supported for ML-KEM")
	}
	if headers.isSet(headerAPV) {
		return nil, errors.New("go-jose/go-jose: apv header is not supported for ML-KEM")
	}

	ek, err := headers.getEK()
	if err != nil {
		return nil, errors.New("go-jose/go-jose: invalid ek header")
	}
	if ek == nil || len(ek.bytes()) == 0 {
		return nil, errors.New("go-jose/go-jose: missing ek header")
	}

	alg := headers.getAlgorithm()
	sharedKey, err := ctx.decapsulate(alg, ek.bytes())
	if err != nil {
		return nil, err
	}

	switch alg {
	case ML_KEM_768, ML_KEM_1024:
		if len(recipient.encryptedKey) != 0 {
			return nil, errors.New("go-jose/go-jose: unexpected JWE Encrypted Key")
		}
		return josecipher.DeriveMLKEM(string(headers.getEncryption()), sharedKey, nil, generator.keySize()), nil
	case ML_KEM_768_A192KW, ML_KEM_1024_A256KW:
	default:
		return nil, ErrUnsupportedAlgorithm
	}

	encryptedKey := recipient.encryptedKey
	if len(encryptedKey) == 0 {
		return nil, errors.New("go-jose/go-jose: missing JWE Encrypted Key")
	}

	kekSize, err := mlkemKeyWrapSize(alg)
	if err != nil {
		return nil, err
	}
	kek := josecipher.DeriveMLKEM(string(alg), sharedKey, nil, kekSize)

	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	return josecipher.KeyUnwrap(block, encryptedKey)
}

func (ctx mlkemDecrypter) decapsulate(alg KeyAlgorithm, ciphertext []byte) ([]byte, error) {
	switch key := ctx.privateKey.(type) {
	case *mlkem.DecapsulationKey768:
		if key == nil {
			return nil, errors.New("go-jose/go-jose: invalid private key")
		}
		switch alg {
		case ML_KEM_768, ML_KEM_768_A192KW:
			return key.Decapsulate(ciphertext)
		}
	case *mlkem.DecapsulationKey1024:
		if key == nil {
			return nil, errors.New("go-jose/go-jose: invalid private key")
		}
		switch alg {
		case ML_KEM_1024, ML_KEM_1024_A256KW:
			return key.Decapsulate(ciphertext)
		}
	}
	return nil, errors.New("go-jose/go-jose: invalid private key")
}

func mlkemEncapsulationKeyForAlgorithm(alg KeyAlgorithm, key interface{}) (mlkemEncapsulationKey, error) {
	switch key := key.(type) {
	case *mlkem.EncapsulationKey768:
		if key == nil {
			return nil, errors.New("go-jose/go-jose: invalid public key")
		}
		switch alg {
		case ML_KEM_768, ML_KEM_768_A192KW:
			return key, nil
		case ML_KEM_1024, ML_KEM_1024_A256KW:
			return nil, errors.New("go-jose/go-jose: invalid public key")
		}
	case *mlkem.EncapsulationKey1024:
		if key == nil {
			return nil, errors.New("go-jose/go-jose: invalid public key")
		}
		switch alg {
		case ML_KEM_1024, ML_KEM_1024_A256KW:
			return key, nil
		case ML_KEM_768, ML_KEM_768_A192KW:
			return nil, errors.New("go-jose/go-jose: invalid public key")
		}
	}

	switch alg {
	case ML_KEM_768, ML_KEM_1024, ML_KEM_768_A192KW, ML_KEM_1024_A256KW:
		return nil, ErrUnsupportedKeyType
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

func mlkemKeyWrapSize(alg KeyAlgorithm) (int, error) {
	switch alg {
	case ML_KEM_768_A192KW:
		return 24, nil
	case ML_KEM_1024_A256KW:
		return 32, nil
	default:
		return 0, ErrUnsupportedAlgorithm
	}
}

func mlkemAlgorithmMatchesPublicKey(alg KeyAlgorithm, key interface{}) bool {
	_, err := mlkemEncapsulationKeyForAlgorithm(alg, key)
	return err == nil
}

func mlkemPublicAlgorithm(alg string) (KeyAlgorithm, error) {
	switch KeyAlgorithm(alg) {
	case ML_KEM_768, ML_KEM_768_A192KW, ML_KEM_1024, ML_KEM_1024_A256KW:
		return KeyAlgorithm(alg), nil
	case "":
		return "", errors.New("go-jose/go-jose: invalid AKP key, missing alg value")
	default:
		return "", fmt.Errorf("go-jose/go-jose: unsupported AKP algorithm '%s'", alg)
	}
}
