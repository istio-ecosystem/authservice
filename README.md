# authservice [![Actions Status](https://github.com/istio-ecosystem/authservice/workflows/Master%20Commit/badge.svg)](https://github.com/istio-ecosystem/authservice/actions)
An implementation of [Envoy](https://envoyproxy.io) [External Authorization](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter),
focused on delivering authN/Z solutions for [Istio](https://istio.io) and [Kubernetes](https://kubernetes.io).

## Introduction
`authservice` helps delegate the [OIDC Authorization Code Grant Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
to the Istio mesh. `authservice` is compatible with any standard OIDC Provider as well as other Istio End-user Auth features,
including [Authentication Policy](https://istio.io/docs/tasks/security/authn-policy/) and [RBAC](https://istio.io/docs/tasks/security/rbac-groups/).
Together, they allow developers to protect their APIs and web apps without any application code required.

Some of the features it provides:
- Transparent login and logout
  - Retrieves OAuth2 Access tokens, ID tokens, and refresh tokens
- Fine-grained control over which url paths are protected
- Session management
  - Configuration of session lifetime and idle timeouts
  - Refreshes expired tokens automatically
- Compatible with any standard OIDC Provider
- Supports multiple OIDC Providers for same application
- Trusts custom CA certs when talking to OIDC Providers
- Works either at the sidecar or gateway level

## Using the `authservice` docker image
The `authservice` images are hosted on [authservice's GitHub Package Registry](https://github.com/istio-ecosystem/authservice/packages).

## Usage
Please refer to the [bookinfo-example](./bookinfo-example) directory for an example of how to use the Authservice.

Refer to the [configuration options guide](docs/README.md) for all of the available configuration options.

## How does authservice work?
We have created a [flowchart](https://miro.com/app/board/o9J_kvus6b4=/) to explain how authservice makes decisions at different points in the login lifecycle.

## Developer Notes
See the [Makefile](Makefile) for common tasks.

We run bazel through [bazelisk](https://github.com/bazelbuild/bazelisk) to make sure we use the correct version of [bazel](https://bazel.build/).
Due to some limitation in current dependencies, we need to request `bazel` dist as "amd64" arch exclusively for both macOS and Linux: for that we require to run
[bazelisk](https://github.com/bazelbuild/bazelisk) through `go run` with `GOARCH` environment variable set to `amd64`. Thus, we require [Go](https://go.dev/doc/install) for building this project.

If you are developing on a Mac, [this setup guide](https://github.com/istio-ecosystem/authservice/wiki/Setting-up-CLion-on-MacOS-for-Authservice-development) may be helpful.

To build authservice with Clang, first setup the `clang.bazelrc` and then build the authservice with `--config=clang` option with bazel.

```
./bazel/setup_clang.sh <path-to-clang>
bazel build //src/main:all  --config clang
```

To Build with FIPS compliant version, add `--define boringssl=fips`.

```
bazel build //src/main:all  --config clang --define boringssl=fips
```

To build with a containeried environment, with customized bazel arguments.

```
export CONTAINER_REGISTRY=gcr.io/your-project
docker build --build-arg bazel_flags="--config=clang" \
  -t ${CONTAINER_REGISTRY}/authservice:latest \
  -f ./build/Dockerfile.build .
```

## Roadmap
See the [authservice github Project](https://github.com/istio-ecosystem/authservice/projects/1)

Additional features being considered:
 - A more Istio-integrated experience of deploying/configuring/enabling `authservice`
 (e.g.: extending Istio Authentication Policy to include `authservice` configs).

## Contributing & Contact
We welcome feedback and contributions. Aside from submitting Github issues/PRs, you can reach out at `#oidc-proposal`
or `#security` channel on [Istio’s Slack](https://istio.slack.com/) workspace
([here's how to join](https://istio.io/about/community/join/)).
