cc_test(
    name = "config_test",
    srcs = ["getconfig_test.cc"],
    data = ["//test/fixtures"],
    deps = [
        "//src/config",
        "@com_google_googletest//:gtest_main",
    ],
    linkstatic = select({"@boost//:osx": True, "//conditions:default": False}), # workaround for not being able to figure out how to link dynamically on MacOS
)
