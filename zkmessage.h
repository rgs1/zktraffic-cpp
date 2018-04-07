#pragma once

#include <iostream>
#include <memory>
#include <sstream>
#include <string>

using namespace std;

namespace Zktraffic {

class ZKMessage {
public:
  ZKMessage(string client, string server) :
    client_(std::move(client)), server_(std::move(server)) {};
  virtual operator std::string() const = 0;

  const string& client() const { return client_; }
  const string& server() const { return server_; }

protected:
  string client_;
  string server_;
};

class ZKClientMessage : public ZKMessage {
public:
  ZKClientMessage(string client, string server) :
    ZKMessage(std::move(client), std::move(server)) {};
  static std::unique_ptr<ZKClientMessage> from_payload(string, string, const string&);
};

class ZKServerMessage : public ZKMessage {
public:
  ZKServerMessage(string client, string server) :
    ZKMessage(std::move(client), std::move(server)) {};
  static std::unique_ptr<ZKServerMessage> from_payload(string, string, const string&);
};

class ConnectRequest : public ZKClientMessage {
public:
  ConnectRequest(string client, string server, int protocol, long long zxid, int timeout,
    long long session, std::string passwd, bool readonly) :
    ZKClientMessage(std::move(client), std::move(server)),
    protocol_(protocol), zxid_(zxid), timeout_(timeout),
    session_(session), passwd_(move(passwd)), readonly_(readonly) {};

  static std::unique_ptr<ConnectRequest> from_payload(string, string, const std::string&);

  operator std::string() const {
    std::stringstream ss;
    ss << "ConnectRequest(\n" <<
      "  client=" << client_ << "\n" <<
      "  server=" << server_ << "\n" <<
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

class PingRequest : public ZKClientMessage {
public:
  PingRequest(string client, string server) :
    ZKClientMessage(std::move(client), std::move(server)) {};

  static std::unique_ptr<PingRequest> from_payload(string, string, const string&);

  operator std::string() const {
    std::stringstream ss;
    ss << "Ping(\n" <<
      "  client=" << client_ << "\n" <<
      "  server=" << server_ << "\n" <<
      ")\n";
    return ss.str();
  };

};

class AuthRequest : public ZKClientMessage {
public:
  AuthRequest(string client, string server, int type, string scheme, string credential) :
    ZKClientMessage(std::move(client), std::move(server)),
    type_(type), scheme_(move(scheme)), credential_(move(credential)) {};

  static std::unique_ptr<AuthRequest> from_payload(string, string, const string&);

  operator std::string() const {
    stringstream ss;
    ss << "AuthRequest(\n" <<
      "  client=" << client_ << "\n" <<
      "  server=" << server_ << "\n" <<
      "  type=" << type_ << "\n" <<
      "  scheme=" << scheme_ << "\n" <<
      "  credential=" << credential_ << "\n" <<
      ")\n";
    return ss.str();
  };

private:
  int type_;
  string scheme_;
  string credential_;
};

}
