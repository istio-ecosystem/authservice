cc_test(
    name = "serviceimpl_test",
    srcs = ["service_impl_test.cc"],
    data = ["//test/fixtures"],
    deps = [
        "//src/config",
        "//src/service:serviceimpl",
        "@com_github_grpc_grpc//:grpc++",
        "@com_google_googletest//:gtest_main",
    ],
    linkstatic = select({"@boost//:osx": True, "//conditions:default": False}), # workaround for not being able to figure out how to link dynamically on MacOS
)
