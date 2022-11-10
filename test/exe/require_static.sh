#!/bin/bash

# This script checks if the given input binary file is static linked or not.
# Copied from https://github.com/envoyproxy/envoy/blob/a12869fa9e9add4301a700978d5489e6a0cc0526/test/exe/envoy_static_test.sh.

if [[ $(uname) == "Darwin" ]]; then
  echo "macOS doesn't support statically linked binaries, skipping."
  exit 0
fi

# We can't rely on the exit code alone, since ldd fails for statically linked binaries.
DYNLIBS=$(ldd "$1" 2>&1) || {
  if [[ ! "${DYNLIBS}" =~ 'not a dynamic executable' ]]; then
      echo "${DYNLIBS}"
      exit 1
  fi
}

if [[ "${DYNLIBS}" =~ libc\+\+ ]]; then
  echo "libc++ is dynamically linked:"
  echo "${DYNLIBS}"
  exit 1
elif [[ "${DYNLIBS}" =~ libstdc\+\+ || "${DYNLIBS}" =~ libgcc ]]; then
  echo "libstdc++ and/or libgcc are dynamically linked:"
  echo "${DYNLIBS}"
  exit 1
fi

# Check for GLIBC dynamic symbols in the binary, see if it matches the version we expect.
go run test/exe/require_glibc.go $1
