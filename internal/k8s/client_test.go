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

package k8s

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetKubeClient(t *testing.T) {
	tests := []struct {
		name       string
		kubeconfig string
		err        error
	}{
		{"unexisting", "non-existing-file", ErrLoadingConfig},
		{"invalid", "testdata/kubeconfig-invalid", ErrCreatingClient},
		{"valid", "testdata/kubeconfig", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("KUBECONFIG", tt.kubeconfig)
			_, err := getKubeClient()
			require.ErrorIs(t, err, tt.err)
		})
	}
}
