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

func TestClockReal(t *testing.T) {
	c := Clock{}
	require.Greater(t, c.Now().Unix(), int64(0))
}

func TestClockCustom(t *testing.T) {
	instant := time.Date(2020, time.January, 2, 3, 4, 5, 6, time.UTC)
	c := Clock{
		NowFn: func() time.Time {
			return instant
		},
	}
	require.Equal(t, instant, c.Now())
}
