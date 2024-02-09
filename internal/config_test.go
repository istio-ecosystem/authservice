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

package internal

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name string
		path string
		err  error
	}{
		{"empty", "", ErrInvalidPath},
		{"invalid", "unexisting", os.ErrNotExist},
		{"valid", "testdata/mock.json", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := LocalConfigFile{path: tt.path}
			require.ErrorIs(t, cfg.Validate(), tt.err)
		})
	}
}

func TestLoadMock(t *testing.T) {
	cfg := LocalConfigFile{path: "testdata/mock.json"}

	require.NoError(t, cfg.Validate())
	require.Len(t, cfg.Config.Chains, 1)
	require.Equal(t, "mock", cfg.Config.Chains[0].Name)
	require.Len(t, cfg.Config.Chains[0].Filters, 1)
	require.True(t, cfg.Config.Chains[0].Filters[0].GetMock().Allow)
}
