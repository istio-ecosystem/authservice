#!/usr/bin/env bash
# Install specific bazel version.
# This script expect to be run with root privileges.
set -e
BAZEL_VERSION="0.29.1"
BAZEL_INSTALLER_SIG="f87f0057cd7d6666e4d371267fbe27a9ed47f42e6663694a1cd755c8c6858baf"

# Required packages.
apt-get update && apt-get upgrade -y && apt-get install -y wget pkg-config zip g++ zlib1g-dev unzip python3 git

# Bazel download, check and installation
mkdir -p /tmp/bazel-install-${BAZEL_VERSION}
pushd /tmp/bazel-install-${BAZEL_VERSION}
wget --quiet https://github.com/bazelbuild/bazel/releases/download/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh
SIG=`sha256sum bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh | awk -F ' ' '{print $1}'`

if [ ${SIG} != ${BAZEL_INSTALLER_SIG} ]; then
    echo ${SIG}
    echo "Bazel installer does not have the expected sha256 checksum" >&2
    exit 1
fi

chmod u+x bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh
./bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh
popd

bazel version

