cc_library(
    name = "mocks",
    hdrs = ["mocks.h"],
    visibility = ["//test:__subpackages__"],
    deps = [
        "//src/common/http",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "http_test",
    srcs = ["http_test.cc"],
    deps = [
        "//src/common/http",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_googletest//:gtest_main",
    ],
    linkstatic = select({"@boost//:osx": True, "//conditions:default": False}), # workaround for not being able to figure out how to link dynamically on MacOS
)
