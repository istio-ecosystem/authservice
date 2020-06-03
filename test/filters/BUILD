cc_test(
    name = "pipe_test",
    srcs = ["pipe_test.cc"],
    deps = [
        "//src/filters:pipe",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_googletest//:gtest_main",
        "@envoy_api//envoy/service/auth/v2:external_auth_cc_grpc",
    ],
    linkstatic = select({"@boost//:osx": True, "//conditions:default": False}), # workaround for not being able to figure out how to link dynamically on MacOS
)

cc_test(
    name = "filter_chain_test",
    srcs = ["filter_chain_test.cc"],
    deps = [
        "//src/filters:filter_chain",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_googletest//:gtest_main",
        "@envoy_api//envoy/service/auth/v2:external_auth_cc_grpc",
        "@com_github_sewenew_redis_plus_plus//:redis_plus_plus",
        "@com_github_redis_hiredis//:hiredis",
    ],
    linkstatic = select({"@boost//:osx": True, "//conditions:default": False}), # workaround for not being able to figure out how to link dynamically on MacOS
)
