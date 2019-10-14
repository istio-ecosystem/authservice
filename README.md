# authservice
An implementation of [Envoy](https://envoyproxy.io) [External Authorization](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter), focused on delivering authN/Z solutions for [Istio](https://istio.io) and [Kubernetes](https://kubernetes.io).

## Introduction
`authservice` can help developers delegate the [OIDC Authorization Code Grant Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth) to the Istio mesh. `authservice` is compatible with any standard OIDC Provier as well as other Istio End-user Auth features, such as [Authentication Policy](https://istio.io/docs/tasks/security/authn-policy/) and [RBAC](https://istio.io/docs/tasks/security/rbac-groups/). Together, they allow developers to protect their APIs and Web Apps without any application code change. 

## Architecture
TBD

## Example
Please refer to the [bookinfo-example](./bookinfo-example) directory for an example integration. 

## Building an `authservice` image
TBD

## Roadmap
Features not yet implemented:
 - Token renewal via refresh token.
 - Start new flow to fetch new tokens when either the ID token or the access token has expired.
 - Support multiple IDPs for the same app.
 - Support adding ext_authz filter and using the `authservice` on the Istio ingress gateway.

Additional features being considered:
 - A more Istio-integrated experience of deploying/configuring/enabling `authservice` 
 (e.g.: extending Istio Authenticaion Policy to include `authservice` configs).  
 
## Contributing & Contact
We welcome feedback and contributions. Aside from submitting Github issues/PRs, you can reach out at `#oidc-proposal` 
or `#security` channel on [Istio’s Slack](https://istio.slack.com/) workspace 
([here's how to join](https://istio.io/about/community/join/)).
