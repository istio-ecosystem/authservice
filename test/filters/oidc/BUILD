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
    linkstatic = select({"@boost//:osx": True, "//conditions:default": False}), # workaround for not being able to figure out how to link dynamically on MacOS
)

cc_test(
    name = "token_response_test",
    srcs = ["token_response_test.cc"],
    deps = [
        "//src/filters/oidc:token_response",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_googletest//:gtest_main",
    ],
    linkstatic = select({"@boost//:osx": True, "//conditions:default": False}), # workaround for not being able to figure out how to link dynamically on MacOS
)

cc_test(
    name = "in_memory_session_store_test",
    srcs = ["in_memory_session_store_test.cc"],
    deps = [
        "//src/filters/oidc:in_memory_session_store",
        "@com_google_googletest//:gtest_main",
    ],
    linkstatic = select({"@boost//:osx": True, "//conditions:default": False}), # workaround for not being able to figure out how to link dynamically on MacOS
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
    linkstatic = select({"@boost//:osx": True, "//conditions:default": False}), # workaround for not being able to figure out how to link dynamically on MacOS
)
