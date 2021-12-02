load("//bazel:bazel.bzl", "authsvc_cc_test")

authsvc_cc_test(
    name = "config_test",
    srcs = ["getconfig_test.cc"],
    data = ["//test/fixtures"],
    deps = [
        "//src/config",
        "@com_google_googletest//:gtest_main",
        "//test/shared:shared_test_helpers"
    ],
)
