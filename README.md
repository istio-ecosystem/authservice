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

## Contributing

To get started:

- [Contributing guide](./CONTRIBUTING.md)
- [Developer guide](./DEVELOPER.md)

## Roadmap
See the [authservice github Project](https://github.com/istio-ecosystem/authservice/projects/1)

Additional features being considered:
 - A more Istio-integrated experience of deploying/configuring/enabling `authservice`
 (e.g.: extending Istio Authentication Policy to include `authservice` configs).

## Contributing & Contact
We welcome feedback and contributions. Aside from submitting Github issues/PRs, you can reach out at `#oidc-proposal`
or `#security` channel on [Istio’s Slack](https://istio.slack.com/) workspace
([here's how to join](https://istio.io/about/community/join/)).
