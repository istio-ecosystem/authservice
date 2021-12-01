load("//bazel:bazel.bzl", "authsvc_cc_test")

authsvc_cc_test(
    name = "pipe_test",
    srcs = ["pipe_test.cc"],
    deps = [
        "//src/filters:pipe",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_googletest//:gtest_main",
    ],
)

authsvc_cc_test(
    name = "filter_chain_test",
    srcs = ["filter_chain_test.cc"],
    deps = [
        "//src/filters:filter_chain",
        "//test/filters/oidc:mocks",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_googletest//:gtest_main",
    ],
)
