# Release process

## Release workflow

The release workflow defined in [`.github/workflows/release.yaml`](./.github/workflows/release.yaml)
will be triggered whenever a tag that matches `v[0-9]+.[0-9]+.[0-9]+**` (examples of valid tags:
`v0.5.0`, `v0.5.1-rc2`) is created. The workflow invokes the `make dist` command to create tarballs
from the combination of `os` (`darwin` and `linux`) with the selected mode (`default`, `clang`, and
`clang-fips`). The tarball name pattern will be: `auth_server_<os>_amd64_<mode>_<version>.tar.gz`.
The version is the same as the given tag with `v` prefix removed. After the tarballs are created,
the workflow uploads the tarballs as attachments to the created release entry on
https://github.com/istio-ecosystem/authservice/releases.
