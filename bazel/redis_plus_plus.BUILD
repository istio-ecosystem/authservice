load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "redis_plus_plus",
    srcs = glob(["src/**/*.cpp"]),
    hdrs = glob([
        "src/**/*.h",
        "src/**/*.hpp",
    ]),
    defines = ["REDIS_PLUS_PLUS_COMPILED_LIB"],
    strip_include_prefix = "src/sw/redis++",
    visibility = ["//visibility:public"],
    deps = ["@com_github_redis_hiredis//:hiredis_headers"],
)
