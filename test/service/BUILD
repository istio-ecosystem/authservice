load("//bazel:bazel.bzl", "authsvc_cc_test")

authsvc_cc_test(
    name = "async_service_impl_test",
    srcs = ["async_service_impl_test.cc"],
    data = ["//test/fixtures"],
    deps = [
        "//src/service:serviceimpl",
        "//src/filters:filter_chain",
        "@com_google_googletest//:gtest_main",
    ],
)

authsvc_cc_test(
    name = "healthcheck_http_server_test",
    srcs = ["healthcheck_http_server_test.cc"],
    data = ["//test/fixtures"],
    deps = [
        "//src/service:healthcheck_http_server_lib",
        "//src/filters:filter_chain",
        "//src/common/http:http",
        "//test/filters/oidc:mocks",
        "@com_google_googletest//:gtest_main",
    ],
)
