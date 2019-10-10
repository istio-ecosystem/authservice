load("//bazel:bazel.bzl", "xx_library")

package(default_visibility = ["//visibility:public"])

xx_library(
    name = "config",
    srcs = ["getconfig.cc"],
    hdrs = [
        "getconfig.h",
    ],
    deps = [
        "//config:config_cc",
    ],
)
