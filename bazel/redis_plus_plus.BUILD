load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "redis_plus_plus",
    deps = ["@com_github_redis_hiredis//:hiredis_headers"],
    srcs = glob(["src/**/*.cpp"]),
    hdrs = glob(["src/**/*.h", "src/**/*.hpp"]),
    visibility = ["//visibility:public"],
    defines = ["REDIS_PLUS_PLUS_COMPILED_LIB"],
    strip_include_prefix = "src/sw/redis++",
)
