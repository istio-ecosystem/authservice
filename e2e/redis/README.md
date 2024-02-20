# Redis e2e tests

The Redis e2e test suite contains tests that verify the correct behavior of the Redis
session store for the OIDC providers. It targets the `SessionStore` interface directly
and verifies the contents of the Redis database on each operation.
