cc_test(
    name = "config_test",
    srcs = ["getconfig_test.cc"],
    data = ["//test/fixtures:valid-config.json", "//test/fixtures:invalid-config.json", "//test/fixtures:invalid-config-with-intermediate-nodes.json"],
    deps = [
        "//src/config:config",
        "@com_google_googletest//:gtest_main",
    ],
)
