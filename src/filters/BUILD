load("//bazel:bazel.bzl", "xx_library")

package(default_visibility = ["//visibility:public"])

xx_library(
    name = "filter",
    srcs = [],
    hdrs = ["filter.h"],
    deps = [
        "@boost//:coroutine",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_google_googleapis//google/rpc:code_cc_proto",
        "@envoy_api//envoy/service/auth/v3:pkg_cc_grpc",
    ],
)

xx_library(
    name = "pipe",
    srcs = ["pipe.cc"],
    hdrs = ["pipe.h"],
    deps = [
        ":filter",
        "@com_github_grpc_grpc//:grpc++",
    ],
)

xx_library(
    name = "filter_chain",
    srcs = [
        "filter_chain.cc",
    ],
    hdrs = [
        "filter_chain.h",
    ],
    deps = [
        "//config:config_cc",
        "//src/config",
        "//src/filters:filter",
        "//src/filters:pipe",
        "//src/filters/oidc:oidc_filter",
        "//src/filters/mock:mock_filter",
        "@com_github_sewenew_redis_plus_plus//:redis_plus_plus",
        "//src/filters/oidc:redis_wrapper",
        "//src/filters/oidc:redis_session_store",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_github_gabime_spdlog//:spdlog",
        "@envoy_api//envoy/service/auth/v3:pkg_cc_grpc",
    ],
)
