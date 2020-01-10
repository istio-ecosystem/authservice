cc_library(
    name = "mocks",
    hdrs = ["mocks.h"],
    visibility = ["//test:__subpackages__"],
    deps = [
        "//src/common/session:token_encryptor",
        "//src/common/session:session_id_generator"
    ],
)

cc_test(
    name = "hkdf_deriver_test",
    srcs = ["hkdf_deriver_test.cc"],
    deps = [
        "//src/common/session:hkdf",
        "@com_google_googletest//:gtest_main",
    ],
    linkstatic = select({"@boost//:osx": True, "//conditions:default": False}), # workaround for not being able to figure out how to link dynamically on MacOS
)

cc_test(
    name = "gcm_encryptor_test",
    srcs = ["gcm_encryptor_test.cc"],
    deps = [
        "//src/common/session:gcm_encryptor",
        "@com_google_googletest//:gtest_main",
    ],
    linkstatic = select({"@boost//:osx": True, "//conditions:default": False}), # workaround for not being able to figure out how to link dynamically on MacOS
)

cc_test(
    name = "session_id_generator_test",
    srcs = ["session_id_generator_test.cc"],
    deps = [
        "//src/common/session:session_id_generator",
        "@com_google_googletest//:gtest_main",
    ],
    linkstatic = select({"@boost//:osx": True, "//conditions:default": False}), # workaround for not being able to figure out how to link dynamically on MacOS
)

cc_test(
    name = "token_encryptor_test",
    srcs = ["token_encryptor_test.cc"],
    deps = [
        "//src/common/session:token_encryptor",
        "@com_google_googletest//:gtest_main",
        "@com_googlesource_boringssl//:crypto",
    ],
    linkstatic = select({"@boost//:osx": True, "//conditions:default": False}), # workaround for not being able to figure out how to link dynamically on MacOS
)
