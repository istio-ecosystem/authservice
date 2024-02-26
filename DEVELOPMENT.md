# Developer guide

All the build targets are self-explanatory and can be listed with:

```bash
$ make help
```

The following software and tools are needed to build the project and run the tests:

* [Go](https://golang.org/dl/)
* [GNU make](https://www.gnu.org/software/make/)
* [Docker](https://docs.docker.com/get-docker/)
* [Kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/) (needed to run the Istio e2e test suite)
* [Helm](https://helm.sh/docs/intro/install/) (needed to run the Istio e2e test suite)


## Building the binary

To build the binary simply run:

```bash
$ make build     # Builds a dynamically linked binary
$ make static    # Builds a statically linked binary
```

The resulting binaries will be in the `bin/` directory. You can play with the 
`TARGETS` environment variable to control the operating systems and architectures you want
to build for.


## Docker image

To build the Docker image, run:

```bash
$ make docker         # Build a single-arch Docker image tagged with "-latest-$arch" 
$ make docker-push    # Build and push the multi-arch Docker images to the registry
```

This will automatically build the required binaries and create a Docker image with them.

The `make docker` target will produce images that are suitable to be used in the `e2e` tests.
The `make docker-push` target will produce multi-arch images and push them to the registry.
You can use the `DOCKER_TARGETS` environment variable to control the operating systems and architectures
you want to build the Docker images for.


## Generating the API code

The configuration options are defined in the [config](config/) directory using [Protocol Buffers](https://protobuf.dev/).
To generate the configuration API code after doing changes to the `.proto` files, run:

```bash
$ make generate
```

There is no need to run `generate` after checking out the code; it's only needed when changes are made to
the `.proto` files.


## Testing

The main testing targets are:

```bash
$ make test     # Run the unit tests
$ make lint     # Run the linters
$ make e2e      # Run the end-to-end tests
```

### e2e tests

The end-to-end tests are found in the [e2e](e2e/) directory. Each subdirectory contains a test suite
that can be run independently. The `make e2e` target will run all the test suites by default. To run
individual suites, simply run `make e2e/<suite>`. For example:

```bash
$ make e2e            # Run all the e2e suites
$ make e2e/keycloak   # Run the 'keycloak' e2e suite

# Examples with custom test options
$ E2E_TEST_OPTS="-v -count=1" make e2e  # Run all the e2e suites with verbose output and no caching
$ E2E_PRESERVE_LOGS=true make e2e       # Preserve the container logs even if tests succeed
```

> [!Note]
> The end-to-end tests use the `authservice` Docker image, and it **must be up-to-date**.  
> Make sure you run `make clean docker` before running the tests

The end-to-end tests use Docker Compose or [KinD](https://kind.sigs.k8s.io/) to set up the required
infrastructure before running the tests.  Once the tests are done, the infrastructure is automatically
torn down if tests pass, or left running  if tests fail, to facilitate troubleshooting. Container logs
are also captured upon test failure, to aid in debugging.

#### Running tests from your IDE

Sometimes it is useful to run the tests from your IDE. To do so, you can start the test infrastructure by
running the `e2e-pre` target from the e2e test suite folder. For example:

```
$ make -C e2e/keycloak e2e-pre
```

Once the infra is up, you can run the tests from your IDE or with a normal `go test` command. After the tests
are done, you can tear down the infrastructure by running the `e2e-post` target.


#### Backward-compatibility tests

The [e2e/legacy](e2e/legacy/) suite directory contains a set of tests that are designed to verify the
backward compatibility of the Auth Service with the older C++ based version. This suite can be run with
the current image and the old image as follows:

```bash
$ E2E_SUITE_MODE=current make e2e/legacy   # Run the suite with the current image
$ E2E_SUITE_MODE=legacy make e2e/legacy    # Run the suite with the old authservice image

# Run the suite with a custom image
$ export E2E_LEGACY_IMAGE=ghcr.io/istio-ecosystem/authservice/authservice:0.5.3
$ E2E_SUITE_MODE=legacy make e2e/legacy
```
