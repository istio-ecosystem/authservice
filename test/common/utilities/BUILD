load("//bazel:bazel.bzl", "authsvc_cc_test", "authsvc_cc_library")

authsvc_cc_library(
    name = "mocks",
    hdrs = ["mocks.h"],
    visibility = ["//test:__subpackages__"],
    deps = [
        "//src/common/utilities:time_service",
        "@com_google_googletest//:gtest",
    ],
)

authsvc_cc_test(
    name = "random_test",
    srcs = ["random_test.cc"],
    deps = [
        "//src/common/utilities:random",
        "@com_google_googletest//:gtest_main",
        "@envoy//bazel:boringssl",
    ],
)

authsvc_cc_test(
    name = "trigger_rules_test",
    srcs = ["trigger_rules_test.cc"],
    deps = [
        "//src/common/utilities:trigger_rules",
        "@com_google_googletest//:gtest_main",
    ],
)
