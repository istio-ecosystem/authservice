# Keycloak e2e tests

The Keycloak e2e test suite contains tests that use the Keycloak OIDC provider. A
Keycloak instance is deployed and configured in the Docker environment as the backend
OIDC provider.

The setup is performed in the [setup-keycloak.sh](setup-keycloak.sh) script, which
configures the default `master` realm with:

* A user named `authservice` with a predefined password.
* A client named `authservice` with a predefined secret.

The user and client will be used in the e2e tests to verify the entire Authorization Code flow.

## Docker host name resolution

The Keycloak end-to-end tests rely on the host `host.docker.internal` to resolve to the host machine,
so you may need to add an entry to your `/etc/hosts` file to make it work. For example:

```bash
$ echo "127.0.0.1  host.docker.internal" >> /etc/hosts
```
