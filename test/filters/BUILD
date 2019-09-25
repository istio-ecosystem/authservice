cc_test(
    name = "pipe_test",
    srcs = ["pipe_test.cc"],
    deps = [
        "//src/filters:pipe",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_googletest//:gtest_main",
        "@envoy_api//envoy/service/auth/v2:external_auth_cc_grpc",
    ],
)
