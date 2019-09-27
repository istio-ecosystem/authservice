#!/usr/bin/env bash
# Install specific bazel version.
# This script expect to be run with root privileges.
set -e
BAZEL_VERSION="0.25.2"
BAZEL_INSTALLER_SIG="5b9ab8a68c53421256909f79c47bde76a051910217531cbf35ee995448254fa7"

# Required packages.
apt-get update && apt-get upgrade -y && apt-get install -y wget pkg-config zip g++ zlib1g-dev unzip python3 git

# Bazel download, check and installation
mkdir -p /tmp/bazel-install
pushd /tmp/bazel-install
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

