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

package authz

import (
	"context"

	envoy "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
)

// Authz is an interface for handling authorization requests.
type Authz interface {
	// Process a CheckRequest and populate a CheckResponse.
	Process(ctx context.Context, req *envoy.CheckRequest, resp *envoy.CheckResponse) error
}
