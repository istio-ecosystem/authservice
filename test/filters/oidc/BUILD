cc_library(
    name = "mocks",
    hdrs = ["mocks.h"],
    deps = [
        "//src/filters/oidc:token_response",
    ],
)

cc_test(
    name = "state_cookie_codec_test",
    srcs = ["state_cookie_codec_test.cc"],
    deps = [
        "//src/filters/oidc:state_cookie_codec",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "token_response_test",
    srcs = ["token_response_test.cc"],
    deps = [
        "//src/filters/oidc:token_response",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "oidc_filter_test",
    srcs = ["oidc_filter_test.cc"],
    deps = [
        "//src/filters/oidc:oidc_filter",
        "//test/common/http:mocks",
        "//test/common/session:mocks",
        "//test/filters/oidc:mocks",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_googletest//:gtest_main",
        "@envoy_api//envoy/service/auth/v2:external_auth_cc_grpc",
    ],
)

cc_test(
    name = "oidc_idp_configuration_test",
    srcs = ["oidc_idp_configuration_test.cc"],
    deps = [
        "//src/filters/oidc:oidc_filter_config",
        "@com_google_googletest//:gtest_main",
    ],
)
