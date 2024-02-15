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

package http

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetPathQueryFragment(t *testing.T) {
	type want struct {
		path, query, fragment string
	}

	tests := []struct {
		path string
		want want
	}{
		{"/", want{path: "/", query: "", fragment: ""}},
		{"/path?query#fragment", want{path: "/path", query: "query", fragment: "fragment"}},
		{"/path", want{path: "/path", query: "", fragment: ""}},
		{"/path?query", want{path: "/path", query: "query", fragment: ""}},
		{"/path#fragment", want{path: "/path", query: "", fragment: "fragment"}},
		{"/?query#fragment", want{path: "/", query: "query", fragment: "fragment"}},
		{"/#fragment", want{path: "/", query: "", fragment: "fragment"}},
		{"/?query", want{path: "/", query: "query", fragment: ""}},
		{"/path?", want{path: "/path", query: "", fragment: ""}},
		{"/path?#", want{path: "/path", query: "", fragment: ""}},
		{"/path?#fragment", want{path: "/path", query: "", fragment: "fragment"}},
		{"/path?query#", want{path: "/path", query: "query", fragment: ""}},
		{"/?que/ry", want{path: "/", query: "que/ry", fragment: ""}},
		{"/#frag/?ment", want{path: "/", query: "", fragment: "frag/?ment"}},
		{"/?query#frag/?ment", want{path: "/", query: "query", fragment: "frag/?ment"}},
		{"/?#", want{path: "/", query: "", fragment: ""}},
		{"/path#fragment?fragment/fragment", want{path: "/path", query: "", fragment: "fragment?fragment/fragment"}},
		{"/path?query/query#fragment/fragment?fragment", want{path: "/path", query: "query/query", fragment: "fragment/fragment?fragment"}},
		{"/path#fragment/fragment?fragment", want{path: "/path", query: "", fragment: "fragment/fragment?fragment"}},
		{"/#fragment/fragment?fragment", want{path: "/", query: "", fragment: "fragment/fragment?fragment"}},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			path, query, fragment := GetPathQueryFragment(tt.path)
			require.Equal(t, tt.want, want{path, query, fragment})
		})
	}
}

func TestEncodeCookieHeader(t *testing.T) {
	tests := []struct {
		name, value string
		directives  []string
		want        string
	}{
		{
			"simple", "value", []string{},
			"simple=value",
		},
		{
			"with-directives", "value", []string{"1", "2", "3"},
			"with-directives=value; 1; 2; 3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeCookieHeader(tt.name, tt.value, tt.directives)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestDecodeCookiesHeader(t *testing.T) {
	tests := []struct {
		cookies string
		want    map[string]string
	}{
		{
			"single=value",
			map[string]string{"single": "value"},
		},
		{
			"multiple=multiple-value; invalid; other=other-value",
			map[string]string{
				"multiple": "multiple-value",
				"other":    "other-value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.cookies, func(t *testing.T) {
			got := DecodeCookiesHeader(tt.cookies)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestBasicAuthHeader(t *testing.T) {
	tests := []struct {
		id, secret string
		want       string
	}{
		{"user", "password", "Basic dXNlcjpwYXNzd29yZA=="},
		{"user", "password with spaces", "Basic dXNlcjpwYXNzd29yZCB3aXRoIHNwYWNlcw=="},
		{"user with spaces", "password", "Basic dXNlciB3aXRoIHNwYWNlczpwYXNzd29yZA=="},
		{"user with spaces", "password with spaces", "Basic dXNlciB3aXRoIHNwYWNlczpwYXNzd29yZCB3aXRoIHNwYWNlcw=="},
	}

	for _, tt := range tests {
		t.Run(tt.id+":"+tt.secret, func(t *testing.T) {
			got := BasicAuthHeader(tt.id, tt.secret)
			require.Equal(t, tt.want, got)

			got2, err := base64.StdEncoding.DecodeString(tt.want[6:])
			require.NoError(t, err)
			require.Equal(t, tt.id+":"+tt.secret, string(got2))
		})
	}
}
