# TODO: Get this from envoy
GO_VERSION = "1.12.5"

# </TODO>

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

http_archive(
    name = "com_github_grpc_grpc",
    strip_prefix = "grpc-1.21.3",
    urls = [
        "https://github.com/grpc/grpc/archive/v1.21.3.tar.gz",
    ],
)

load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")

## TODO: These are required by envoy API but not included in api_dependencies()
http_archive(
    name = "io_bazel_rules_go",
    sha256 = "a82a352bffae6bee4e95f68a8d80a70e87f42c4741e6a448bec11998fcc82329",
    urls = [
        "https://github.com/bazelbuild/rules_go/releases/download/0.18.5/rules_go-0.18.5.tar.gz",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

http_archive(
    name = "bazel_gazelle",
    sha256 = "3c681998538231a2d24d0c07ed5a7658cb72bfb5fd4bf9911157c0e9ac6a2687",
    urls = ["https://github.com/bazelbuild/bazel-gazelle/releases/download/0.17.0/bazel-gazelle-0.17.0.tar.gz"],
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")

# Needed for `bazel fetch` to work with @com_google_protobuf
# https://github.com/google/protobuf/blob/v3.6.1/util/python/BUILD#L6-L9
bind(
    name = "python_headers",
    actual = "@com_google_protobuf//util/python:python_headers",
)

http_archive(
    name = "six",
    build_file = "six.BUILD",
    strip_prefix = "protobuf-3.7.1",
    urls = ["https://github.com/protocolbuffers/protobuf/releases/download/v3.7.1/protobuf-all-3.7.1.tar.gz"],
)
## </TODO>

# Envoy API definitions

## We import envoy_api as a sub-repo of the mono-repo
git_repository(
    name = "envoy",
    commit = "f1f436c76174a78b557bc2f47965c883650c68bd",
    remote = "https://github.com/thales-e-security/envoy.git",
    verbose = True,
)

load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

load("@envoy//bazel:repositories.bzl", "GO_VERSION", "envoy_dependencies")
load("@envoy//bazel:cc_configure.bzl", "cc_configure")

envoy_dependencies()

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

go_rules_dependencies()

go_register_toolchains(go_version = GO_VERSION)

grpc_deps()

# External dependencies
_SPDLOG_WORKSPACE = """"""

_SPDLOG_BUILD = """
cc_library(
    name = "spdlog",
    srcs = glob(["src/**/*.cpp"]),
    hdrs = glob(["include/**/*.h"]),
    visibility = ["//visibility:public"],
    defines = ["SPDLOG_COMPILED_LIB"],
    strip_include_prefix = "include",
)

cc_library(
    name = "spdlog_headers",
    hdrs = glob(["include/**/*.h"]),
    visibility = ["//visibility:public"],
    defines = ["SPDLOG_COMPILED_LIB"],
)
"""

http_archive(
    name = "com_github_gabime_spdlog",
    build_file_content = _SPDLOG_BUILD,
    strip_prefix = "spdlog-1.3.1",
    urls = [
        "https://github.com/gabime/spdlog/archive/v1.3.1.tar.gz",
    ],
    workspace_file_content = _SPDLOG_WORKSPACE,
)

git_repository(
    name = "com_googlesource_boringssl",
    commit = "105694d8387d60f33b729a236deda4ea6bd16e24",
    remote = "https://boringssl.googlesource.com/boringssl",
)

git_repository(
    name = "com_github_abseil-cpp",
    commit = "e6b050212c859fbaf67abac76105da10ec348274",
    remote = "https://github.com/abseil/abseil-cpp",
)

git_repository(
    name = "com_google_googleapis",
    commit = "b4c73face84fefb967ef6c72f0eae64faf67895f",
    remote = "https://github.com/googleapis/googleapis",
)

load("@com_google_googleapis//:repository_rules.bzl", "switched_rules_by_language")

switched_rules_by_language(
    name = "com_google_googleapis_imports",
    cc = True,
)

_BOOST_WORKSPACE = """"""

_BOOST_BUILD = """
cc_library(
    name = "all",
    hdrs = glob(["boost/**/*"], exclude = ["boost/**/*.cpp"]),
    includes = ["boost"],
    include_prefix = "boost",
    strip_include_prefix = "boost",
    visibility = ["//visibility:public"],
    deps = [],
)
"""

http_archive(
    name = "boost",
    build_file_content = _BOOST_BUILD,
    strip_prefix = "boost_1_70_0",
    urls = [
        "https://dl.bintray.com/boostorg/release/1.70.0/source/boost_1_70_0.tar.gz",
    ],
    workspace_file_content = _BOOST_WORKSPACE,
)

git_repository(
    name = "com_github_google_jwt_verify_lib",
    commit = "0f14d43f20381cfae0469cb2309b2e220c0f0ea3",
    remote = "https://github.com/google/jwt_verify_lib",
)

# Test dependencies

http_archive(
    name = "com_google_googletest",
    strip_prefix = "googletest-release-1.8.1",
    urls = [
        "https://github.com/google/googletest/archive/release-1.8.1.tar.gz",
    ],
)
