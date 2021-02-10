load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def oidcservice_dependencies():
  zlib()
  com_envoyproxy_envoy()
  com_github_grpc_grpc()
  com_google_googletest()
  com_google_abseil()
  boost()
  com_github_redis_hiredis()
  com_github_sewenew_redis_plus_plus()
  com_github_google_jwt_verify_lib()
  com_googlesource_boringssl()
  io_bazel_rules_go()
  bazel_gazelle()
  com_envoyproxy_protoc_gen_validate()
  rules_foreign_cc()

def com_envoyproxy_envoy():
  http_archive(
    name = "envoy",
    sha256 = "b19ececd6baab2855eb2f92c531ec5f86625aea7fc3f8b2624023c6915dc94b7",
    urls = ["https://github.com/envoyproxy/envoy/archive/v1.17.0.tar.gz"],
    strip_prefix = "envoy-1.17.0",
  )

def com_github_grpc_grpc():
  http_archive(
    name = "com_github_grpc_grpc",
    sha256 = "7372a881122cd85a7224435a1d58bc5e11c88d4fb98a64b83f36f3d1c2f16d39",
    urls = ["https://github.com/grpc/grpc/archive/v1.34.0.tar.gz"],
    strip_prefix = "grpc-1.34.0",
  )

def com_google_googletest():
  http_archive(
    name = "com_google_googletest",
    sha256 = "9dc9157a9a1551ec7a7e43daea9a694a0bb5fb8bec81235d8a1e6ef64c716dcb",
    strip_prefix = "googletest-release-1.10.0",
    urls = ["https://github.com/google/googletest/archive/release-1.10.0.tar.gz"],
  )

def com_google_abseil():
  http_archive(
    name = "com_github_abseil-cpp",
    sha256 = "e3812f256dd7347a33bf9d93a950cf356c61c0596842ff07d8154cd415145d83",
    strip_prefix = "abseil-cpp-5d8fc9192245f0ea67094af57399d7931d6bd53f",
    urls = ["https://github.com/abseil/abseil-cpp/archive/5d8fc9192245f0ea67094af57399d7931d6bd53f.tar.gz"],
  )

def boost():
  http_archive(
    name = "boost",
    build_file = "//bazel:BUILD.boost",
    strip_prefix = "boost_1_70_0",
    urls = [
        "https://dl.bintray.com/boostorg/release/1.70.0/source/boost_1_70_0.tar.gz",
        "https://downloads.sourceforge.net/project/boost/boost/1.70.0/boost_1_70_0.tar.gz",
    ],
    sha256 = "882b48708d211a5f48e60b0124cf5863c1534cd544ecd0664bb534a4b5d506e9",
  )

def com_github_redis_hiredis():
  http_archive(
    name = "com_github_redis_hiredis",
    build_file = "//bazel:hiredis.BUILD",
    strip_prefix = "hiredis-0.14.1",
    urls = [
      "https://github.com/redis/hiredis/archive/v0.14.1.tar.gz",
    ],
  )

def com_github_sewenew_redis_plus_plus():
  http_archive(
    name = "com_github_sewenew_redis_plus_plus",
    build_file = "//bazel:redis_plus_plus.BUILD",
    strip_prefix = "redis-plus-plus-1.1.1",
    urls = [
      "https://github.com/sewenew/redis-plus-plus/archive/1.1.1.tar.gz",
    ],
  )

def com_github_google_jwt_verify_lib():
  http_archive(
    name = "com_github_google_jwt_verify_lib",
    sha256 = "7a5c35b7cbf633398503ae12cad8c2833e92b3a796eed68b6256d22d51ace5e1",
    strip_prefix = "jwt_verify_lib-28efec2e4df1072db0ed03597591360ec9f80aac",
    urls = [
      "https://github.com/google/jwt_verify_lib/archive/28efec2e4df1072db0ed03597591360ec9f80aac.tar.gz"
    ],
  )

def com_googlesource_boringssl():
  http_archive(
    name = "com_googlesource_boringssl",
    sha256 = "15d855e5ec7c28b6b99159f1c6bbc7803e1623ed540f637174c6b88e7abd001c",
    strip_prefix = "boringssl-936ca21922d266a31e3309144b082bdb3a689af7",
    urls = [
      "https://github.com/google/boringssl/archive/936ca21922d266a31e3309144b082bdb3a689af7.tar.gz"
    ],
  )

def zlib():
  http_archive(
    name = "zlib",
    build_file = "@com_google_protobuf//:third_party/zlib.BUILD",
    sha256 = "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1",
    strip_prefix = "zlib-1.2.11",
    urls = [
        "https://mirror.bazel.build/zlib.net/zlib-1.2.11.tar.gz",
        "https://zlib.net/zlib-1.2.11.tar.gz",
    ],
  )

def bazel_gazelle():
  http_archive(
    name = "bazel_gazelle",
    sha256 = "b85f48fa105c4403326e9525ad2b2cc437babaa6e15a3fc0b1dbab0ab064bc7c",
    urls = [
      "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.22.2/bazel-gazelle-v0.22.2.tar.gz"
    ]
  )

def io_bazel_rules_go():
  http_archive(
    name = "io_bazel_rules_go",
    sha256 = "6f111c57fd50baf5b8ee9d63024874dd2a014b069426156c55adbf6d3d22cb7b",
    urls = ["https://github.com/bazelbuild/rules_go/releases/download/v0.25.0/rules_go-v0.25.0.tar.gz"],
  )

def com_envoyproxy_protoc_gen_validate():
  http_archive(
    name = "com_envoyproxy_protoc_gen_validate",
    strip_prefix = "protoc-gen-validate-872b28c457822ed9c2a5405da3c33f386ac0e86f",
    sha256 = "388ea2261bc1d2c6ef6ec01bfaa3aec451aedb245e23514033ccc9b5cc10c4ab",
    urls = [
      "https://github.com/envoyproxy/protoc-gen-validate/archive/872b28c457822ed9c2a5405da3c33f386ac0e86f.tar.gz",
    ],
  )

def rules_foreign_cc():
  http_archive(
    name = "io_bazel_rules_foreign_cc",
    sha256 = "e7446144277c9578141821fc91c55a61df7ae01bda890902f7286f5fd2f6ae46",
    urls = ["https://github.com/bazelbuild/rules_foreign_cc/archive/d54c78ab86b40770ee19f0949db9d74a831ab9f0.tar.gz"]
  )
