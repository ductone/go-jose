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

import "fmt"

const akpThumbprintTemplate = `{"alg":"%s","kty":"AKP","pub":"%s"}`

func isMLDSAAlgorithm(alg SignatureAlgorithm) bool {
	switch alg {
	case ML_DSA_44, ML_DSA_65, ML_DSA_87:
		return true
	default:
		return false
	}
}

func isCompositeAlgorithm(alg SignatureAlgorithm) bool {
	switch alg {
	case ML_DSA_44_ES256, ML_DSA_65_ES256, ML_DSA_87_ES384, ML_DSA_44_Ed25519, ML_DSA_65_Ed25519:
		return true
	default:
		return false
	}
}

func isPQSignatureAlgorithm(alg SignatureAlgorithm) bool {
	return isMLDSAAlgorithm(alg) || isCompositeAlgorithm(alg)
}

func akpThumbprintInput(alg string, pub []byte) (string, error) {
	if alg == "" {
		return "", fmt.Errorf("go-jose/go-jose: invalid AKP key, missing alg value")
	}
	if len(pub) == 0 {
		return "", fmt.Errorf("go-jose/go-jose: invalid AKP key, missing pub value")
	}
	return fmt.Sprintf(akpThumbprintTemplate, alg, newBuffer(pub).base64()), nil
}

func unsupportedGo127(feature string) error {
	return fmt.Errorf("%w: %s requires Go 1.27 or newer", ErrUnsupportedAlgorithm, feature)
}
