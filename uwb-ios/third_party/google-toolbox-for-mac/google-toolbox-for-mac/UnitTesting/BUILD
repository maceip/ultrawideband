load("@rules_cc//cc:defs.bzl", "objc_library")
load("@build_bazel_rules_apple//apple:ios.bzl", "ios_build_test")
load("@build_bazel_rules_apple//apple:macos.bzl", "macos_build_test")

objc_library(
    name = "TestTimer",
    testonly = 1,
    hdrs = [
        "GTMTestTimer.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//:Defines",
    ],
)

objc_library(
    name = "SenTestCase",
    testonly = 1,
    hdrs = [
        "GTMSenTestCase.h",
    ],
    non_arc_srcs = [
        "GTMSenTestCase.m",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//:Defines",
    ],
)

ios_build_test(
    name = "iOSBuildTest",
    minimum_os_version = "12.0",
    targets = [
        ":TestTimer",
        ":SenTestCase",
    ],
)

macos_build_test(
    name = "macOSBuildTest",
    minimum_os_version = "10.10",
    targets = [
        ":TestTimer",
        ":SenTestCase",
    ],
)
