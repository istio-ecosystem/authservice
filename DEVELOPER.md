# Developer documentation

Authservice (main binary name: `auth_server`) is built using Bazel build system. Every submitted
commit is checked (by running tests and build jobs) by our CI on GitHub Actions.

We run [`bazel`](https://bazel.build/) through [`bazelisk`](https://github.com/bazelbuild/bazelisk)
to make sure we use the correct version of `bazel`. Due to some limitation in current dependencies,
we need to request `bazel` dist as "amd64" arch exclusively for both macOS and Linux: for that we
require to run [bazelisk](https://github.com/bazelbuild/bazelisk) through `go run` with `GOARCH`
environment variable set to `amd64`. Thus, we require [Go 1.17.x](https://go.dev/doc/install) or
later to build this project.

Please invoke `make help` (or you can also inspecting the main [`Makefile`](./Makefile)) for
available targets.

To build authservice with `clang`, firstly, you need to setup the `clang.bazelrc`. This can be
accomplished by:

```console
make clang.bazelrc
BAZEL_FLAGS="--config clang" make build
```

To Build with FIPS compliant version, add `--define boringssl=fips`.

```console
make clang.bazelrc
BAZEL_FLAGS="--config clang --define boringssl=fips" make build
```
