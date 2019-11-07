load("//bazel:bazel.bzl", "xx_binary")

package(default_visibility = ["//visibility:public"])

xx_binary(
    name = "auth-server",
    srcs = ["auth-server.cc"],
    deps = [
        "//src/config",
        "//src/service:serviceimpl",
        "@com_github_abseil-cpp//absl/flags:parse",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_github_grpc_grpc//:grpc++",
        "@envoy_api//envoy/service/auth/v2:external_auth_cc",
    ],
)
