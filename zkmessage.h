#pragma once

#include <iostream>
#include <memory>
#include <sstream>
#include <string>

using namespace std;

namespace Zktraffic {

class ZKMessage {
public:
  ZKMessage() {};
  virtual operator std::string() const = 0;

private:
};

class ZKClientMessage : public ZKMessage {
public:
  ZKClientMessage() {};
  static std::unique_ptr<ZKClientMessage> from_payload(const std::string&);

private:
};

class ZKServerMessage : public ZKMessage {
public:
  ZKServerMessage() {};
  static std::unique_ptr<ZKServerMessage> from_payload(const std::string&);

private:
};

class ZKConnectRequest : public ZKClientMessage {
public:
  ZKConnectRequest(int protocol, long long zxid, int timeout,
    long long session, std::string passwd, bool readonly) :
    protocol_(protocol), zxid_(zxid), timeout_(timeout),
    session_(session), passwd_(passwd), readonly_(readonly) {};

  static std::unique_ptr<ZKConnectRequest> from_payload(const std::string&);

  operator std::string() const {
    std::stringstream ss;
    ss << "ZKConnectRequest(\n" <<
      "  timeout=" << timeout_ << "\n" <<
      "  readonly=" << readonly_ << "\n" <<
      ")\n";
    return ss.str();
  };

private:
  int protocol_;
  long long zxid_;
  int timeout_;
  long long session_;
  std::string passwd_;
  bool readonly_;
};

}
