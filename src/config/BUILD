load("//bazel:bazel.bzl", "xx_library")

package(default_visibility = ["//visibility:public"])

xx_library(
    name = "config",
    srcs = ["get_config.cc"],
    hdrs = [
        "get_config.h",
    ],
    deps = [
        "//config:config_cc",
        "@boost//:all",
        "@com_github_gabime_spdlog//:spdlog",
    ],
)
