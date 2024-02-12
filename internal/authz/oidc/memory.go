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
	"sync"
	"time"

	"github.com/tetratelabs/telemetry"

	"github.com/tetrateio/authservice-go/internal"
)

var _ SessionStore = (*memoryStore)(nil)

// memoryStore is an in-memory implementation of the SessionStore interface.
type memoryStore struct {
	log                    telemetry.Logger
	clock                  Clock
	absoluteSessionTimeout time.Duration
	idleSessionTimeout     time.Duration

	mu       sync.Mutex
	sessions map[string]*session
}

// NewMemoryStore creates a new in-memory session store.
func NewMemoryStore(clock Clock, absoluteSessionTimeout, idleSessionTimeout time.Duration) SessionStore {
	return &memoryStore{
		log:                    internal.Logger(internal.Session).With("type", "memory"),
		clock:                  clock,
		absoluteSessionTimeout: absoluteSessionTimeout,
		idleSessionTimeout:     idleSessionTimeout,
		sessions:               make(map[string]*session),
	}
}

func (m *memoryStore) SetTokenResponse(sessionID string, tokenResponse *TokenResponse) {
	m.set(sessionID, func(s *session) {
		s.tokenResponse = tokenResponse
	})
}

func (m *memoryStore) GetTokenResponse(sessionID string) *TokenResponse {
	m.mu.Lock()
	defer m.mu.Unlock()

	s := m.sessions[sessionID]
	if s == nil {
		return nil
	}

	s.accessed = m.clock.Now()
	return s.tokenResponse
}

func (m *memoryStore) SetAuthorizationState(sessionID string, authorizationState *AuthorizationState) {
	m.set(sessionID, func(s *session) {
		s.authorizationState = authorizationState
	})
}

func (m *memoryStore) GetAuthorizationState(sessionID string) *AuthorizationState {
	m.mu.Lock()
	defer m.mu.Unlock()

	s := m.sessions[sessionID]
	if s == nil {
		return nil
	}

	s.accessed = m.clock.Now()
	return s.authorizationState
}

func (m *memoryStore) ClearAuthorizationState(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s := m.sessions[sessionID]; s != nil {
		s.accessed = m.clock.Now()
		s.authorizationState = nil
	}
}

func (m *memoryStore) RemoveSession(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, sessionID)
}

func (m *memoryStore) RemoveAllExpired() {
	var (
		earliestTimeAddedToKeep    = m.clock.Now().Add(-m.absoluteSessionTimeout)
		earliestTimeIdleToKeep     = m.clock.Now().Add(-m.idleSessionTimeout)
		shouldCheckAbsoluteTimeout = m.absoluteSessionTimeout > 0
		shouldCheckIdleTimeout     = m.idleSessionTimeout > 0
	)

	m.mu.Lock()
	defer m.mu.Unlock()

	for sessionID, s := range m.sessions {
		expiredBasedOnTimeAdded := shouldCheckAbsoluteTimeout && s.added.Before(earliestTimeAddedToKeep)
		expiredBasedOnIdleTime := shouldCheckIdleTimeout && s.accessed.Before(earliestTimeIdleToKeep)

		if expiredBasedOnTimeAdded || expiredBasedOnIdleTime {
			delete(m.sessions, sessionID)
		}
	}
}

// set the given session with the given setter function and record the access time.
func (m *memoryStore) set(sessionID string, setter func(s *session)) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s := m.sessions[sessionID]
	if s != nil {
		s.accessed = m.clock.Now()
		setter(s)
	} else {
		s = newSession(m.clock.Now())
		setter(s)
		m.sessions[sessionID] = s
	}
}

// session holds the data of a session stored in the in-memory cache
type session struct {
	tokenResponse      *TokenResponse
	authorizationState *AuthorizationState
	added              time.Time
	accessed           time.Time
}

// newSession creates a new session with the given creation time.
func newSession(t time.Time) *session {
	return &session{
		added:    t,
		accessed: t,
	}
}