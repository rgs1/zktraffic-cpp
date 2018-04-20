# zktraffic-cpp [![Build Status](https://travis-ci.org/rgs1/zktraffic-cpp.svg?branch=master)](https://travis-ci.org/rgs1/zktraffic-cpp)

**Table of Contents**

- [tl;dr](#tldr)
- [Building](#building)
- [Using](#using)

### tl;dr ###

ZooKeeper protocol analyzer and stats gathering daemon (C++ clone of [https://github.com/twitter/zktraffic](https://github.com/twitter/zktraffic)).

### Building ###

You'll need [bazel](https://bazel.build/). To build zkdump:

```
$ bazel build //src:zkdump
```

### Using ###
Once you've built it, run zkdump:

```
$ sudo bazel-bin/src/zkdump lo  # or eth0,etc. instead of lo
running (iface: lo)
ConnectRequest(
  client=127.0.0.1:59656
  server=127.0.0.1:2181
  timeout=10000
  readonly=0
)

Ping(
  client=127.0.0.1:59656
  server=127.0.0.1:2181
)

PingReply(
  client=127.0.0.1:59656
  server=127.0.0.1:2181
  xid=-2
  zxid=33
  error=0
)

...
```
