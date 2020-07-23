load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

# Envoy API definitions

## We import envoy_api as a sub-repo of the mono-repo
git_repository(
    name = "envoy",
    commit = "41932e9e6f3c932f37f77ae0a5191d65bb7ec8eb",
    remote = "https://github.com/envoyproxy/envoy.git",
    verbose = True,
)

load("@envoy//bazel:api_binding.bzl", "envoy_api_binding")

envoy_api_binding()

load("@envoy//bazel:api_repositories.bzl", "envoy_api_dependencies")

envoy_api_dependencies()

load("@envoy//bazel:repositories.bzl", "envoy_dependencies")

envoy_dependencies()

load("@envoy//bazel:dependency_imports.bzl", "envoy_dependency_imports")

envoy_dependency_imports()

# Protobuf generator dependencies
http_archive(
    name = "com_envoyproxy_protoc_gen_validate",
    urls = [
        "https://github.com/envoyproxy/protoc-gen-validate/archive/v0.1.0.tar.gz",
    ],
)

#  gRPC dependencies
http_archive(
    name = "com_github_grpc_grpc",
    strip_prefix = "grpc-1.21.3",
    urls = [
        "https://github.com/grpc/grpc/archive/v1.21.3.tar.gz",
    ],
)

load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")

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

http_archive(
    name = "boost",
    build_file = "//bazel:BUILD.boost",
    strip_prefix = "boost_1_70_0",
    urls = [
        "https://dl.bintray.com/boostorg/release/1.70.0/source/boost_1_70_0.tar.gz",
        "https://downloads.sourceforge.net/project/boost/boost/1.70.0/boost_1_70_0.tar.gz",
    ],
    sha256 = "882b48708d211a5f48e60b0124cf5863c1534cd544ecd0664bb534a4b5d506e9",
)

git_repository(
    name = "com_github_google_jwt_verify_lib",
    commit = "945805866007edb9d2760915abaa672ed8b7da86",
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

_HIREDIS_WORKSPACE= """"""

_HIREDIS_BUILD = """
cc_library(
    name = "hiredis",
    srcs=glob(["*.c"], exclude=["test.c"]),
    hdrs=glob(["*.h"]),
    textual_hdrs=["dict.c"],
    visibility = ["//visibility:public"],
    defines = ["HIREDIS_COMPILED_LIB"],
)

cc_library(
    name = "hiredis_headers",
    hdrs=glob(["*.h"]),
    visibility = ["//visibility:public"],
    include_prefix = "hiredis",
)
"""

http_archive(
    name = "com_github_redis_hiredis",
    build_file_content = _HIREDIS_BUILD,
    strip_prefix = "hiredis-0.14.1",
    urls = [
        "https://github.com/redis/hiredis/archive/v0.14.1.tar.gz",
    ],
    workspace_file_content = _HIREDIS_WORKSPACE,
)

# redis-plus-plus
_REDIS_PLUS_PLUS_WORKSPACE = """"""

_REDIS_PLUS_PLUS_BUILD = """
cc_library(
    name = "redis_plus_plus",
    deps = ["@com_github_redis_hiredis//:hiredis_headers"],
    srcs = glob(["src/**/*.cpp"]),
    hdrs = glob(["src/**/*.h", "src/**/*.hpp"]),
    visibility = ["//visibility:public"],
    defines = ["REDIS_PLUS_PLUS_COMPILED_LIB"],
    strip_include_prefix = "src/sw/redis++",
)
"""

http_archive(
    name = "com_github_sewenew_redis_plus_plus",
    build_file_content = _REDIS_PLUS_PLUS_BUILD,
    strip_prefix = "redis-plus-plus-1.1.1",
    urls = [
        "https://github.com/sewenew/redis-plus-plus/archive/1.1.1.tar.gz",
    ],
    workspace_file_content = _REDIS_PLUS_PLUS_WORKSPACE,
)

