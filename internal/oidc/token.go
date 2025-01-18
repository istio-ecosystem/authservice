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
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

// TokenResponse contains information about the tokens returned by the Identity Provider.
type TokenResponse struct {
	IDToken              string
	AccessToken          string
	AccessTokenExpiresAt time.Time
	RefreshToken         string
}

// ParseIDToken parses the ID token string and returns the token and an error if any.
func (t *TokenResponse) ParseIDToken() (jwt.Token, error) { return ParseToken(t.IDToken) }

// ParseToken parses the token string and returns the token and an error if any.
func ParseToken(token string) (jwt.Token, error) {
	return jwt.Parse([]byte(token), jwt.WithValidate(false), jwt.WithVerify(false))
}
