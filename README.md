# authservice

[![CI](https://github.com/istio-ecosystem/authservice/actions/workflows/ci.yaml/badge.svg)](https://github.com/istio-ecosystem/authservice/actions/workflows/ci.yaml)

An implementation of [Envoy](https://envoyproxy.io) [External Authorization](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter),
focused on delivering authN/Z solutions for [Istio](https://istio.io) and [Kubernetes](https://kubernetes.io).

## Introduction

`authservice` helps delegate the [OIDC Authorization Code Grant Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
to the Istio mesh. `authservice` is compatible with any standard OIDC Provider as well as other Istio End-user Auth features,
including [Authentication Policy](https://istio.io/docs/tasks/security/authn-policy/) and [RBAC](https://istio.io/docs/tasks/security/rbac-groups/).
Together, they allow developers to protect their APIs and web apps without any application code required.

Some of the features it provides:
* Transparent login and logout
  * Retrieves OAuth2 Access tokens, ID tokens, and refresh tokens
* Fine-grained control over which url paths are protected
* Session management
  * Configuration of session lifetime and idle timeouts
  * Refreshes expired tokens automatically
* Compatible with any standard OIDC Provider
* Supports multiple OIDC Providers for same application
* Trusts custom CA certs when talking to OIDC Providers
* Works either at the sidecar or gateway level


## How does authservice work?

[This flowchart](https://miro.com/app/board/o9J_kvus6b4=/) explains how `authservice`
makes decisions at different points in the login lifecycle.

## Contributing

Contributions are very welcome! Please read the [Contributing guidelines](CONTRIBUTING.md)
to get started.

Detailed development instructions can be found in the [Development guide](DEVELOPMENT.md).
