#!/usr/bin/env bash

set -eux

script_dir=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
cd ${script_dir}/..

ISTIO_VERSION=1.4.0
curl -L https://git.io/getLatestIstio | ISTIO_VERSION=${ISTIO_VERSION} sh -
