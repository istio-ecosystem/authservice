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

import "time"

// Clock represents a source of current time.
type Clock struct {
	// Override for time.Now.
	NowFn func() time.Time
}

// Now returns the current local time.
func (s *Clock) Now() time.Time {
	if s.NowFn != nil {
		return s.NowFn()
	}
	return time.Now()
}
