load("//bazel:bazel.bzl", "xx_library")

package(default_visibility = ["//visibility:public"])

xx_library(
    name = "filter",
    hdrs = ["filter.h"],
    deps = [
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_google_googleapis//google/rpc:code_cc_proto",
        "@envoy_api//envoy/service/auth/v2:external_auth_cc_grpc",
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
