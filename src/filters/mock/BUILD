load("//bazel:bazel.bzl", "authsvc_cc_library")

package(default_visibility = ["//visibility:public"])

authsvc_cc_library(
    name = "mock_filter",
    srcs = ["mock_filter.cc"],
    hdrs = ["mock_filter.h"],
    deps = [
        "//config/mock:config_cc",
        "//src/filters:filter",
        "//src/filters:filter_factory",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_google_googleapis//google/rpc:code_cc_proto",
    ],
)
