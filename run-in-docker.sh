#!/usr/bin/env bash

# Copyright 2025 Tetrate
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script runs the given command in a Docker container.

if [[ ${#} -lt 2 ]]; then
    echo "Usage: ${0} <platform> <command>"
    echo "  e.g: ${0} linux/amd64 make help"
    exit 1
fi

set -e

ROOT=$(git rev-parse --show-toplevel)
GO_VERSION=$(sed -ne 's/^go //gp' "${ROOT}/go.mod")
BUILD_IMAGE="golang:${GO_VERSION}"

docker run \
    --rm \
    --platform "${1}" \
    -v "${PWD}":/source \
    -v "$(go env GOMODCACHE)":/go/pkg/mod \
    -e GOPROXY="$(go env GOPROXY)" \
    -e GOPRIVATE="$(go env GOPRIVATE)" \
    -w /source \
    "${BUILD_IMAGE}" \
    /bin/bash -c "git config --global --add safe.directory /source ; ${*:2}"
