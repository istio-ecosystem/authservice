cc_test(
    name = "async_service_impl_test",
    srcs = ["async_service_impl_test.cc"],
    data = ["//test/fixtures"],
    deps = [
        "//src/service:serviceimpl",
        "//src/filters:filter_chain",
        "@com_google_googletest//:gtest_main",
    ],
    linkstatic = select({"@boost//:osx": True, "//conditions:default": False}), # workaround for not being able to figure out how to link dynamically on MacOS
)
