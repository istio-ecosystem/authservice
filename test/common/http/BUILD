load("//bazel:bazel.bzl", "authsvc_cc_test", "authsvc_cc_library")

authsvc_cc_library(
    name = "mocks",
    hdrs = ["mocks.h"],
    visibility = ["//test:__subpackages__"],
    deps = [
        "//src/common/http",
        "@com_google_googletest//:gtest",
    ],
)

authsvc_cc_test(
    name = "http_test",
    srcs = ["http_test.cc"],
    deps = [
        "//src/common/http",
        "//test/shared:shared_test_helpers",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_googletest//:gtest_main",
    ],
)
