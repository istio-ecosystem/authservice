cc_test(
    name = "pipe_test",
    srcs = ["pipe_test.cc"],
    deps = [
        "//src/filters:pipe",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_googletest//:gtest_main",
        "@envoy_api//envoy/service/auth/v2:pkg_cc_grpc",
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
        "@envoy_api//envoy/service/auth/v2:pkg_cc_grpc",
    ],
    linkstatic = select({"@boost//:osx": True, "//conditions:default": False}), # workaround for not being able to figure out how to link dynamically on MacOS
)
