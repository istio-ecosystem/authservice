cc_library(
    name = "mocks",
    hdrs = ["mocks.h"],
    visibility = ["//test:__subpackages__"],
    deps = [
        "//src/common/utilities:time_service",
        "@com_google_googletest//:gtest",
    ],
)

cc_test(
    name = "random_test",
    srcs = ["random_test.cc"],
    deps = [
        "//src/common/utilities:random",
        "@com_google_googletest//:gtest_main",
    ],
    linkstatic = select({"@boost//:osx": True, "//conditions:default": False}), # workaround for not being able to figure out how to link dynamically on MacOS
)
