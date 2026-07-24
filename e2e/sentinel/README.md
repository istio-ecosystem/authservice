# Redis Sentinel e2e tests

The Redis Sentinel e2e test suite verifies the Sentinel-aware Redis session store. It
runs a Redis master, a replica and a single Sentinel, connects through a
`redis+sentinel://` server URI, and verifies that session writes recover after the
master is stopped and the Sentinel promotes the replica.
