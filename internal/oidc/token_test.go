// Copyright 2025 Tetrate
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oidc

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

func TestParseIDToken(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		tr := &TokenResponse{
			IDToken: newToken(),
		}

		it, err := tr.ParseIDToken()
		require.NoError(t, err)
		require.Equal(t, "authservice", it.Issuer())
	})

	t.Run("invalid", func(t *testing.T) {
		tr := &TokenResponse{}
		_, err := tr.ParseIDToken()
		require.Error(t, err)
	})
}

func newToken() string {
	token, _ := jwt.NewBuilder().
		Issuer("authservice").
		Subject("user").
		Expiration(time.Now().Add(time.Hour)).
		Build()
	signed, _ := jwt.Sign(token, jwt.WithKey(jwa.HS256, []byte("key")))
	return string(signed)
}
