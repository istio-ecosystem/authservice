load("//bazel:bazel.bzl", "xx_library")

package(default_visibility = ["//visibility:public"])

xx_library(
    name = "session_string_generator",
    srcs = [
        "session_string_generator.cc",
    ],
    hdrs = [
        "session_string_generator.h",
    ],
    deps = [
        "//src/common/utilities:random"
    ],
)
