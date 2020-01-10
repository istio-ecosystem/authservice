load("//bazel:bazel.bzl", "xx_library")

package(default_visibility = ["//visibility:public"])

xx_library(
    name = "hkdf",
    srcs = [
        "hkdf_deriver.cc",
    ],
    hdrs = [
        "hkdf_deriver.h",
    ],
    deps = [
        "@com_googlesource_boringssl//:crypto",
    ],
)

xx_library(
    name = "gcm_encryptor",
    srcs = [
        "gcm_encryptor.cc",
    ],
    hdrs = [
        "gcm_encryptor.h",
    ],
    deps = [
        "@com_github_abseil-cpp//absl/types:optional",
        "@com_googlesource_boringssl//:crypto",
    ],
)

xx_library(
    name = "session_id_generator",
    srcs = [
        "session_id_generator.cc",
    ],
    hdrs = [
        "session_id_generator.h",
    ],
    deps = [
        "//src/common/utilities:random"
    ],
)

xx_library(
    name = "token_encryptor",
    srcs = [
        "token_encryptor.cc",
    ],
    hdrs = [
        "token_encryptor.h",
    ],
    deps = [
        ":gcm_encryptor",
        ":hkdf",
        "//src/common/utilities:random",
        "@com_github_abseil-cpp//absl/strings:strings",
        "@com_googlesource_boringssl//:crypto",
    ],
)
