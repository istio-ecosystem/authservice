// Copyright 2024 Tetrate
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

package mock

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	testEnvoyURL    = "http://localhost:8080"
	testAuthzHeader = "X-Authz-Decision"

	excludedPath = "/excluded"
	includedPath = "/included"
)

func TestMock(t *testing.T) {
	t.Run("allow-equality", func(t *testing.T) {
		req, err := http.NewRequest("GET", withPath(includedPath), nil)
		require.NoError(t, err)
		req.Header.Set(testAuthzHeader, "allow")

		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, 200, res.StatusCode)
	})

	t.Run("allow-prefix", func(t *testing.T) {
		req, err := http.NewRequest("GET", withPath(includedPath), nil)
		require.NoError(t, err)
		req.Header.Set(testAuthzHeader, "ok-prefix")

		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, 200, res.StatusCode)
	})

	t.Run("deny-header", func(t *testing.T) {
		req, err := http.NewRequest("GET", withPath(includedPath), nil)
		require.NoError(t, err)
		req.Header.Set(testAuthzHeader, "non-match")

		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, 403, res.StatusCode)
	})

	t.Run("deny", func(t *testing.T) {
		res, err := http.Get(withPath(includedPath))

		require.NoError(t, err)
		require.Equal(t, 403, res.StatusCode)
	})

	// excluded path should not be affected by the header since the auth service checks are not triggered.
	t.Run("allow-non-matching-header-for-excluded-path", func(t *testing.T) {
		req, err := http.NewRequest("GET", withPath(excludedPath), nil)
		require.NoError(t, err)
		req.Header.Set(testAuthzHeader, "non-match")

		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, 200, res.StatusCode)
	})
}

func withPath(p string) string {
	return testEnvoyURL + p
}
