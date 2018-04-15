#pragma once

#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

namespace Zktraffic {

class Acl {
public:
  Acl(int perms, string scheme, string credential) :
    perms_(perms), scheme_(move(scheme)), credential_(move(credential)) {};

  operator std::string() const { return repr(true); }

  string repr(bool newlines=false) const {
    auto nl = newlines ? "\n" : "";
    auto prefix = newlines ? "  " : "";
    stringstream ss;
    ss << "Acl(" <<  nl <<
      prefix << "perms=" << perms_ << "," << nl <<
      prefix << "scheme=" << scheme_ << "," << nl <<
      prefix << "credential=" << credential_ << nl <<
      ")" << nl;
    return ss.str();
  };

private:
  int perms_;
  string scheme_;
  string credential_;
};

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
  ZKClientMessage(string client, string server, string path) :
    ZKMessage(std::move(client), std::move(server)), path_(move(path)) {};
  ZKClientMessage(string client, string server, string path, bool watch) :
    ZKMessage(std::move(client), std::move(server)), path_(move(path)), watch_(watch) {};
  ZKClientMessage(string client, string server, string path, int version) :
    ZKMessage(std::move(client), std::move(server)), path_(move(path)), version_(version) {};
  static std::unique_ptr<ZKClientMessage> from_payload(string, string, const string&);

protected:
  string req_version(const string& req) const {
    stringstream ss;
    ss << req << "(\n" <<
      "  client=" << client_ << "\n" <<
      "  server=" << server_ << "\n" <<
      "  path=" << path_ << "\n" <<
      "  version=" << version_ << "\n" <<
      ")\n";
    return ss.str();
  }
  string req_watch(const string& req) const {
    stringstream ss;
    ss << req << "(\n" <<
      "  client=" << client_ << "\n" <<
      "  server=" << server_ << "\n" <<
      "  path=" << path_ << "\n" <<
      "  watch=" << watch_ << "\n" <<
      ")\n";
    return ss.str();
  }
  string req_path(const string& req) const {
    stringstream ss;
    ss << req << "(\n" <<
      "  client=" << client_ << "\n" <<
      "  server=" << server_ << "\n" <<
      "  path=" << path_ << "\n" <<
      ")\n";
    return ss.str();
  }
  string path_;
  bool watch_;
  int version_;
};

class ZKServerMessage : public ZKMessage {
public:
  ZKServerMessage(string client, string server, int xid, long long zxid, int error) :
    ZKMessage(move(client), move(server)), xid_(xid), zxid_(zxid), error_(error) {};
  static std::unique_ptr<ZKServerMessage> from_payload(string, string, const string&);

protected:
  string reply(const string& replytype) const {
    stringstream ss;
    ss << replytype << "(\n" <<
      "  client=" << client_ << "\n" <<
      "  server=" << server_ << "\n" <<
      "  xid=" << xid_ << "\n" <<
      "  zxid=" << zxid_ << "\n" <<
      "  error=" << error_ << "\n" <<
      ")\n";
    return ss.str();
  }
  int xid_;
  long long zxid_;
  int error_;
};

class PingReply : public ZKServerMessage {
public:
  PingReply(string client, string server, int xid, long long zxid, int error) :
    ZKServerMessage(move(client), move(server), xid, zxid, error) {};

  operator std::string() const { return reply("PingReply"); }
};

template <typename T>
constexpr uint32_t enumToInt(T val) {
  return static_cast<uint32_t>(val);
}

enum class EventType {
  CREATED = 1,
  DELETED = 2,
  CHANGED = 3,
  CHILD = 4
};

enum class State {
  DISCONNECTED = 0,
  NO_SYNC_CONNECTED = 1,
  SYNC_CONNECTED = 3,
  AUTH_FAILED = 4,
  CONNECTED_READ_ONLY = 5,
  SASL_AUTHENTICATED = 6,
  EXPIRED = -112
};

class WatchEvent : public ZKServerMessage {
public:
  WatchEvent(string client, string server, int xid, long long zxid, int error,
    int event_type, int state, string path) :
    ZKServerMessage(move(client), move(server), xid, zxid, error),
    event_type_(event_type), state_(state), path_(move(path)) {};

  static std::unique_ptr<WatchEvent> from_payload(string, string, const std::string&, int, long long, int);
  operator std::string() const {
    stringstream ss;
    ss << "WatchEvent(\n" <<
      "  client=" << client_ << "\n" <<
      "  server=" << server_ << "\n" <<
      "  xid=" << xid_ << "\n" <<
      "  zxid=" << zxid_ << "\n" <<
      "  error=" << error_ << "\n" <<
      "  event_type=" << event_to_name(event_type_) << "\n" <<
      "  state=" << state_to_name(state_) << "\n" <<
      "  path=" << path_ << "\n" <<
      ")\n";
    return ss.str();
  }

protected:
  int event_type_;
  int state_;
  string path_;

private:
  const char * event_to_name(int event) const {
    switch (event) {
    case enumToInt(EventType::CREATED):
      return "created";
    case enumToInt(EventType::DELETED):
      return "deleted";
    case enumToInt(EventType::CHANGED):
      return "changed";
    case enumToInt(EventType::CHILD):
      return "child";
    }

    return "unknown";
  }

  const char * state_to_name(int state) const {
    switch (state) {
    case enumToInt(State::DISCONNECTED):
      return "disconnected";
    case enumToInt(State::NO_SYNC_CONNECTED):
      return "no_sync_connected";
    case enumToInt(State::SYNC_CONNECTED):
      return "sync_connected";
    case enumToInt(State::AUTH_FAILED):
      return "auth_failed";
    case enumToInt(State::CONNECTED_READ_ONLY):
      return "read_only";
    case enumToInt(State::SASL_AUTHENTICATED):
      return "sasl_authenticated";
    case enumToInt(State::EXPIRED):
      return "expired";
    }

    return "unknown";
  }
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

class GetRequest : public ZKClientMessage {
public:
  GetRequest(string client, string server, string path, bool watch) :
    ZKClientMessage(move(client), move(server), move(path), watch) {};

  static std::unique_ptr<GetRequest> from_payload(string, string, const string&);
  operator std::string() const { return req_watch("GetRequest"); }
};

class CreateRequest : public ZKClientMessage {
public:
  CreateRequest(string client, string server, string path,
    bool ephemeral, bool sequence, vector<Acl> acls) :
    ZKClientMessage(move(client), move(server), move(path)),
    ephemeral_(ephemeral), sequence_(sequence), acls_(move(acls)) {};

  static std::unique_ptr<CreateRequest> from_payload(string, string, const string&);

  operator std::string() const {
    auto ephemeral = ephemeral_ ? "true" : "false";
    auto sequence = sequence_ ? "true" : "false";
    stringstream ss;
    ss << "CreateRequest(\n" <<
      "  client=" << client_ << "\n" <<
      "  server=" << server_ << "\n" <<
      "  path=" << path_ << "\n" <<
      "  ephemeral=" << ephemeral << "\n" <<
      "  sequence=" << sequence << "\n" <<
      "  acls=" << acls() << "\n" <<
      ")\n";
    return ss.str();
  };

private:
  string acls() const {
    bool first = true;
    stringstream ss;
    for (auto acl: acls_) {
      if (!first)
	ss << ",";
      ss << acl.repr();
      first = false;
    }
    return ss.str();
  };
  bool ephemeral_;
  bool sequence_;
  vector<Acl> acls_;
};

class SetRequest : public ZKClientMessage {
public:
  SetRequest(string client, string server, string path, int version) :
    ZKClientMessage(move(client), move(server), move(path), version) {};

  operator std::string() const { return req_version("SetRequest"); }
};

class DeleteRequest : public ZKClientMessage {
public:
  DeleteRequest(string client, string server, string path, int version) :
    ZKClientMessage(move(client), move(server), move(path), version) {};

  operator std::string() const { return req_version("DeleteRequest"); }
};

class GetChildrenRequest : public ZKClientMessage {
public:
  GetChildrenRequest(string client, string server, string path, bool watch) :
    ZKClientMessage(move(client), move(server), move(path), watch) {};

  operator std::string() const { return req_watch("GetChildrenRequest"); }
};

class ExistsRequest : public ZKClientMessage {
public:
  ExistsRequest(string client, string server, string path, bool watch) :
    ZKClientMessage(move(client), move(server), move(path), watch) {};

  operator std::string() const { return req_watch("ExistsRequest"); }
};

class SyncRequest : public ZKClientMessage {
public:
  SyncRequest(string client, string server, string path) :
    ZKClientMessage(move(client), move(server), move(path)) {};

  operator std::string() const { return req_path("SyncRequest"); }
};

} // Zktraffic
