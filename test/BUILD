cc_test(
    name = "sniffer-test",
    srcs = ["sniffer-test.cc"],
    copts = ["-Iexternal/gtest/include"],
    deps = [
        "@googletest//:gtest_main",
        "//src:zktraffic",
    ],
    data = [
        "//test:data/basic.pcap"
    ]
)
