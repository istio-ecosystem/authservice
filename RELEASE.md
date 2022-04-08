# Release process

## Release workflow

The release workflow defined in [`.github/workflows/release.yaml`](./.github/workflows/release.yaml)
will be triggered whenever a tag that matches `[0-9]+.[0-9]+.[0-9]+**` (examples of valid tags:
`0.5.0`, `0.5.1-rc2`) is created. The workflow invokes the `make dist` command to create tarballs
from the combination of `os` (`darwin` and `linux`) with the selected mode (`default`, `clang`, and
`clang-fips`). The tarball name pattern will be: `auth_server_<os>_amd64_<mode>_<version>.tar.gz`.
After the tarballs are created, the workflow uploads the tarballs as attachments to the created
release entry on https://github.com/istio-ecosystem/authservice/releases.

## Make a Release

To make a release, create an tag at the commit you want. For example

```sh
git tag -a "0.5.1"
git push upstsream HEAD # You must have admin permission for the repo.
```

Github Action will detect the newly created tags and trigger the workflow. Check [Action Runs](https://github.com/istio-ecosystem/authservice/actions)
and watch for its completion.

Once workflow completes, go to [Release](https://github.com/istio-ecosystem/authservice/releases)
page and draft the release notes, provide Docker image links.
