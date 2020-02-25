cc_library(
    name = "mocks",
    hdrs = ["mocks.h"],
    visibility = ["//test:__subpackages__"],
    deps = [
        "//src/common/session:session_string_generator"
    ],
)

cc_test(
    name = "session_string_generator_test",
    srcs = ["session_string_generator_test.cc"],
    deps = [
        "//src/common/session:session_string_generator",
        "@com_google_googletest//:gtest_main",
    ],
    linkstatic = select({"@boost//:osx": True, "//conditions:default": False}), # workaround for not being able to figure out how to link dynamically on MacOS
)
