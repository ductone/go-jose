//go:build !go1.27

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
	"errors"
	"strings"
	"testing"
)

func TestPQAlgorithmsRequireGo127(t *testing.T) {
	algs := []SignatureAlgorithm{
		ML_DSA_44,
		ML_DSA_65,
		ML_DSA_87,
		ML_DSA_44_ES256,
		ML_DSA_65_ES256,
		ML_DSA_87_ES384,
		ML_DSA_44_Ed25519,
		ML_DSA_65_Ed25519,
	}

	for _, alg := range algs {
		_, err := NewSigner(SigningKey{Algorithm: alg, Key: nil}, nil)
		if !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Fatalf("NewSigner(%s) error = %v, want ErrUnsupportedAlgorithm", alg, err)
		}
		if !strings.Contains(err.Error(), "Go 1.27") {
			t.Fatalf("NewSigner(%s) error = %q, want Go 1.27 requirement", alg, err)
		}
	}
}

func TestAKPJWKRequiresGo127(t *testing.T) {
	var jwk JSONWebKey
	err := jwk.UnmarshalJSON([]byte(`{"kty":"AKP","alg":"ML-DSA-44","pub":"AA"}`))
	if !errors.Is(err, ErrUnsupportedKeyType) {
		t.Fatalf("UnmarshalJSON(AKP) error = %v, want ErrUnsupportedKeyType", err)
	}
}
