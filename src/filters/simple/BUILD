load("//bazel:bazel.bzl", "xx_library")

package(default_visibility = ["//visibility:public"])

xx_library(
    name = "simple_filter",
    srcs = ["simple_filter.cc"],
    hdrs = ["simple_filter.h"],
    deps = [
        "//config/simple:config_cc",
        "//src/filters:filter",
        "@com_github_gabime_spdlog//:spdlog",
        "@com_google_googleapis//google/rpc:code_cc_proto",
    ],
)
