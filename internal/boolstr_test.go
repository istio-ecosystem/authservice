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

package internal

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestBoolStrValue(t *testing.T) {
	tests := []struct {
		name string
		in   *structpb.Value
		want bool
	}{
		{"empty", &structpb.Value{}, false},
		{"bool", &structpb.Value{Kind: &structpb.Value_BoolValue{BoolValue: true}}, true},
		{"string-true", &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: "true"}}, true},
		{"string-false", &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: "false"}}, false},
		{"string-invalid", &structpb.Value{Kind: &structpb.Value_StringValue{StringValue: "invalid"}}, false},
		{"type-mismatch", &structpb.Value{Kind: &structpb.Value_ListValue{}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, BoolStrValue(tt.in))
		})
	}
}
