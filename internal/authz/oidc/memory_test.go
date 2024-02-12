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

package oidc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTokenResponse(t *testing.T) {
	m := NewMemoryStore(Clock{}, 0, 0).(*memoryStore)

	require.Nil(t, m.GetTokenResponse("s1"))

	// Create a session and verify it's added and accessed time
	tr := &TokenResponse{}
	m.SetTokenResponse("s1", &TokenResponse{})
	require.Greater(t, m.sessions["s1"].added.Unix(), int64(0))
	require.Equal(t, m.sessions["s1"].added, m.sessions["s1"].accessed)

	// Verify that the right token response is returned and the accessed time is updated
	require.Equal(t, tr, m.GetTokenResponse("s1"))
	require.True(t, m.sessions["s1"].accessed.After(m.sessions["s1"].added))
	lastAccessed := m.sessions["s1"].accessed

	// Verify that updating the token response also updates the session access timestamp
	m.SetTokenResponse("s1", &TokenResponse{})
	require.True(t, m.sessions["s1"].accessed.After(lastAccessed))
}

func TestAuthorizationState(t *testing.T) {
	m := NewMemoryStore(Clock{}, 0, 0).(*memoryStore)

	as := m.GetAuthorizationState("s1")
	require.Nil(t, as)

	// Create a session and verify it's added and accessed time
	as = &AuthorizationState{}
	m.SetAuthorizationState("s1", as)
	require.Greater(t, m.sessions["s1"].added.Unix(), int64(0))
	require.Equal(t, m.sessions["s1"].added, m.sessions["s1"].accessed)

	// Verify that the right state is returned and the accessed time is updated
	require.Equal(t, as, m.GetAuthorizationState("s1"))
	lastAccessed := m.sessions["s1"].accessed
	require.True(t, lastAccessed.After(m.sessions["s1"].added))

	// Verify that updating the authz state also updates the session access timestamp
	m.SetAuthorizationState("s1", &AuthorizationState{})
	require.True(t, m.sessions["s1"].accessed.After(lastAccessed))

	// Verify that clearing the authz state also updates the session access timestamp
	m.ClearAuthorizationState("s1")
	require.Nil(t, m.GetAuthorizationState("s1"))
	require.True(t, m.sessions["s1"].accessed.After(lastAccessed))
}

func TestRemoveResponse(t *testing.T) {
	m := NewMemoryStore(Clock{}, 0, 0).(*memoryStore)

	m.SetTokenResponse("s1", &TokenResponse{})
	require.NotNil(t, m.sessions["s1"])

	m.RemoveSession("s1")
	require.Nil(t, m.sessions["s1"])
}

func TestRemoveAllExpired(t *testing.T) {
	m := NewMemoryStore(Clock{}, 0, 0).(*memoryStore)

	m.SetTokenResponse("s1", &TokenResponse{})
	m.SetTokenResponse("s2", &TokenResponse{})
	m.SetTokenResponse("abs-expired", &TokenResponse{})
	m.SetTokenResponse("idle-expired", &TokenResponse{})

	m.sessions["abs-expired"].added = time.Now().Add(-time.Hour)
	m.sessions["idle-expired"].accessed = time.Now().Add(-time.Hour)

	t.Run("no-expiration", func(t *testing.T) {
		m.RemoveAllExpired()

		require.Len(t, m.sessions, 4)
		require.NotNil(t, m.sessions["s1"])
		require.NotNil(t, m.sessions["s2"])
		require.NotNil(t, m.sessions["abs-expired"])
		require.NotNil(t, m.sessions["idle-expired"])
	})

	t.Run("expiration", func(t *testing.T) {
		m.absoluteSessionTimeout = time.Minute
		m.idleSessionTimeout = time.Minute
		m.RemoveAllExpired()

		require.Len(t, m.sessions, 2)
		require.NotNil(t, m.sessions["s1"])
		require.NotNil(t, m.sessions["s2"])
		require.Nil(t, m.sessions["abs-expired"])
		require.Nil(t, m.sessions["idle-expired"])

	})
}
