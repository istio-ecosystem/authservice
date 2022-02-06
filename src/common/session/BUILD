load("//bazel:bazel.bzl", "authsvc_cc_library")

package(default_visibility = ["//visibility:public"])

authsvc_cc_library(
    name = "session_string_generator",
    srcs = [
        "session_string_generator.cc",
    ],
    hdrs = [
        "session_string_generator.h",
    ],
    deps = [
        "//src/common/utilities:random",
    ],
)
