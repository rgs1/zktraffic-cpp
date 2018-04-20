#pragma once

#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

using namespace std;

namespace Zktraffic {

const int CONNECT_XID = 0;
const int WATCH_XID = -1;
const int PING_XID = -2;
const int AUTH_XID = -4;
const int SET_WATCHES_XID = -8;

enum class Opcodes {
  CONNECT = 0,
  CREATE = 1,
  DELETE = 2,
  EXISTS = 3,
  GETDATA = 4,
  SETDATA = 5,
  GETACL = 6,
  SETACL = 7,
  GETCHILDREN = 8,
  SYNC = 9,
  PING = 11,
  GETCHILDREN2 = 12,
  CHECK = 13,
  MULTI = 14,
  CREATE2 = 15,
  RECONFIG = 16,
  CREATESESSION = -10,
  CLOSE = -11,
  SETAUTH = 100,
  SETWATCHES = 101
};

class ZnodeStat {
public:
  ZnodeStat(long long czxid, long long mzxid, unsigned long long ctime, unsigned long long mtime,
    int version, int cversion, int aversion, long long ephemeralOwner,
    int dataLength, int numChildren, long long pzxid) :
    czxid_(czxid), mzxid_(mzxid), ctime_(ctime), mtime_(mtime),
    version_(version), cversion_(cversion), aversion_(aversion),
    ephemeralOwner_(ephemeralOwner), dataLength_(dataLength),
    numChildren_(numChildren), pzxid_(pzxid) {}

  operator std::string() const {
    stringstream ss;
    ss << "Stat(" <<
      "czxid=" << czxid_ << "," <<
      "mzxid=" << mzxid_ << "," <<
      "ctime=" << ctime_ << "," <<
      "mtime=" << mtime_ << "," <<
      "version=" << version_ << "," <<
      "cversion=" << cversion_ << "," <<
      "aversion=" << aversion_ << "," <<
      "ephemeralOwner=" << ephemeralOwner_ << "," <<
      "dataLength=" << dataLength_ << "," <<
      "numChildren=" << numChildren_ << "," <<
      "pzxid=" << pzxid_ <<
      ")";
    return ss.str();
  }

protected:
  long long czxid_;
  long long mzxid_;
  unsigned long long ctime_;
  unsigned long long mtime_;
  int version_;
  int cversion_;
  int aversion_;
  long long ephemeralOwner_;
  int dataLength_;
  int numChildren_;
  long long pzxid_;
};

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

template <typename T>
constexpr uint32_t enumToInt(T val) {
  return static_cast<uint32_t>(val);
}

class ZKMessage {
public:
  ZKMessage(string client, string server, int xid) :
    client_(std::move(client)), server_(std::move(server)), xid_(xid) {};
  virtual operator std::string() const = 0;

  const string& client() const { return client_; }
  const string& server() const { return server_; }
  int xid() { return xid_; }

protected:
  static const char * opcode_to_name(int opcode) {
    switch (opcode) {
    case enumToInt(Opcodes::SETWATCHES):
      return "SETWATCHES";
    case enumToInt(Opcodes::SETAUTH):
      return "SETAUTH";
    case enumToInt(Opcodes::CLOSE):
      return "CLOSE";
    case enumToInt(Opcodes::CREATESESSION):
      return "CREATESESSION";
    case enumToInt(Opcodes::RECONFIG):
      return "RECONFIG";
    case enumToInt(Opcodes::CREATE2):
      return "CREATE2";
    case enumToInt(Opcodes::MULTI):
      return "MULTI";
    case enumToInt(Opcodes::CHECK):
      return "CHECK";
    case enumToInt(Opcodes::GETCHILDREN2):
      return "GETCHILDREN2";
    case enumToInt(Opcodes::PING):
      return "PING";
    case enumToInt(Opcodes::SYNC):
      return "SYNC";
    case enumToInt(Opcodes::GETCHILDREN):
      return "GETCHILDREN";
    case enumToInt(Opcodes::SETACL):
      return "SETACL";
    case enumToInt(Opcodes::GETACL):
      return "GETACL";
    case enumToInt(Opcodes::SETDATA):
      return "SETDATA";
    case enumToInt(Opcodes::GETDATA):
      return "GETDATA";
    case enumToInt(Opcodes::EXISTS):
      return "EXISTS";
    case enumToInt(Opcodes::DELETE):
      return "DELETE";
    case enumToInt(Opcodes::CREATE):
      return "CREATE";
    case enumToInt(Opcodes::CONNECT):
      return "CONNECT";
    }
    return "unknown";
  }
  string client_;
  string server_;
  int xid_;
};

class ZKClientMessage : public ZKMessage {
public:
  ZKClientMessage(string client, string server, int xid) :
    ZKMessage(move(client), move(server), xid) {};
  ZKClientMessage(string client, string server, int xid, string path) :
    ZKMessage(move(client), move(server), xid), path_(move(path)) {};
  ZKClientMessage(string client, string server, int xid, string path, bool watch) :
    ZKMessage(move(client), move(server), xid), path_(move(path)), watch_(watch) {};
  ZKClientMessage(string client, string server, int xid, string path, int version) :
    ZKMessage(move(client), move(server), xid), path_(move(path)), version_(version) {};
  static std::unique_ptr<ZKClientMessage> from_payload(string, string, const string&);
  virtual int opcode() const = 0;

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
      "  xid=" << xid_ << "\n" <<
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
    ZKMessage(move(client), move(server), xid), zxid_(zxid), error_(error) {};
  static std::unique_ptr<ZKServerMessage> from_payload(string, string,
      const string&, const unordered_map<int, int>&);

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
  string reply_data(const string& reply, const string& fname, const string& data) const {
    stringstream ss;
    ss << reply << "(\n" <<
      "  client=" << client_ << "\n" <<
      "  server=" << server_ << "\n" <<
      "  xid=" << xid_ << "\n" <<
      "  zxid=" << zxid_ << "\n" <<
      "  error=" << error_ << "\n" <<
      "  " << fname << "=" << data << "\n" <<
      ")\n";
    return ss.str();
  }
  string reply_data_stat(const string& reply, const string& fname, const string& data, const string& stat) const {
    stringstream ss;
    ss << reply << "(\n" <<
      "  client=" << client_ << "\n" <<
      "  server=" << server_ << "\n" <<
      "  xid=" << xid_ << "\n" <<
      "  zxid=" << zxid_ << "\n" <<
      "  error=" << error_ << "\n" <<
      "  " << fname << "=" << data << "\n" <<
      "  stat=" << stat << "\n" <<
      ")\n";
    return ss.str();
  }
  string reply_vec_stat(const string& reply, const string& fname, const vector<string>& vec, const string& stat) const {
    stringstream ss;
    ss << reply << "(\n" <<
      "  client=" << client_ << "\n" <<
      "  server=" << server_ << "\n" <<
      "  xid=" << xid_ << "\n" <<
      "  zxid=" << zxid_ << "\n" <<
      "  error=" << error_ << "\n" <<
      "  " << fname << "=" << join(vec, ",") << "\n" <<
      "  stat=" << stat << "\n" <<
      ")\n";
    return ss.str();
  }
  string reply_stat(const string& reply, const string& stat) const {
    stringstream ss;
    ss << reply << "(\n" <<
      "  client=" << client_ << "\n" <<
      "  server=" << server_ << "\n" <<
      "  xid=" << xid_ << "\n" <<
      "  zxid=" << zxid_ << "\n" <<
      "  error=" << error_ << "\n" <<
      "  stat=" << stat << "\n" <<
      ")\n";
    return ss.str();
  }
  string join(const vector<string>& vec, const string& delim) const {
    bool first = true;
    stringstream ss;
    for (auto s: vec) {
      if (!first)
	ss << delim;
      ss << s;
      first = false;
    }
    return ss.str();
  }
  long long zxid_;
  int error_;
};

class PingReply : public ZKServerMessage {
public:
  PingReply(string client, string server, long long zxid, int error) :
    ZKServerMessage(move(client), move(server), PING_XID, zxid, error) {};

  operator std::string() const { return reply("PingReply"); }
};

class GetReply : public ZKServerMessage {
public:
  GetReply(string client, string server, int xid, long long zxid, int error) :
    ZKServerMessage(move(client), move(server), xid, zxid, error),
    data_(nullptr), stat_(nullptr) {};

  GetReply(string client, string server, int xid, long long zxid, int error,
    string data, unique_ptr<ZnodeStat> stat) :
    ZKServerMessage(move(client), move(server), xid, zxid, error),
	data_(move(data)), stat_(move(stat)) {};

  operator std::string() const {
    auto& data = error_ ? "" : data_;
    string stat = "";
    if (!error_)
      stat = *stat_.get();
    return reply_data_stat("GetReply", "data", data, stat);
  }

private:
  string data_;
  unique_ptr<ZnodeStat> stat_;
};

class CreateReply : public ZKServerMessage {
public:
  CreateReply(string client, string server, int xid, long long zxid, int error, string path) :
    ZKServerMessage(move(client), move(server), xid, zxid, error),
    path_(move(path)), stat_(nullptr) {};

  CreateReply(string client, string server, int xid, long long zxid, int error) :
    ZKServerMessage(move(client), move(server), xid, zxid, error),
    path_(nullptr), stat_(nullptr) {};

  CreateReply(string client, string server, int xid, long long zxid, int error,
    string path, unique_ptr<ZnodeStat> stat) :
    ZKServerMessage(move(client), move(server), xid, zxid, error),
	path_(move(path)), stat_(move(stat)) {};

  operator std::string() const {
    const auto name = stat_ == nullptr ? "CreateReply" : "Create2Reply";
    auto& data = error_ ? "" : path_;
    string stat = "";
    if (!error_ && stat_ != nullptr)
      stat = *stat_.get();
    return reply_data_stat(name, "path", data, stat);
  }

private:
  string path_;
  unique_ptr<ZnodeStat> stat_;
};

class GetChildrenReply : public ZKServerMessage {
public:
  GetChildrenReply(string client, string server, int xid, long long zxid, int error, vector<string> children) :
    ZKServerMessage(move(client), move(server), xid, zxid, error),
    children_(move(children)), stat_(nullptr) {};

  GetChildrenReply(string client, string server, int xid, long long zxid, int error) :
    ZKServerMessage(move(client), move(server), xid, zxid, error),
    children_(vector<string>{}), stat_(nullptr) {};

  GetChildrenReply(string client, string server, int xid, long long zxid, int error,
    vector<string> children, unique_ptr<ZnodeStat> stat) :
    ZKServerMessage(move(client), move(server), xid, zxid, error),
	children_(move(children)), stat_(move(stat)) {};

  operator std::string() const {
    const auto name = stat_ == nullptr ? "GetChildrenReply" : "GetChildren2Reply";
    string stat = "";
    if (!error_ && stat_ != nullptr)
      stat = *stat_.get();
    return reply_vec_stat(name, "children", children_, stat);
  }

private:
  vector<string> children_{};
  unique_ptr<ZnodeStat> stat_;
};

class SetReply : public ZKServerMessage {
public:
  SetReply(string client, string server, int xid, long long zxid, int error) :
    ZKServerMessage(move(client), move(server), xid, zxid, error), stat_(nullptr) {};

  SetReply(string client, string server, int xid, long long zxid, int error,
    unique_ptr<ZnodeStat> stat) :
    ZKServerMessage(move(client), move(server), xid, zxid, error), stat_(move(stat)) {};

  operator std::string() const {
    string stat = "";
    if (!error_ && stat_ != nullptr)
      stat = *stat_.get();
    return reply_stat("SetReply", stat);
  }

private:
  unique_ptr<ZnodeStat> stat_;
};

class DeleteReply : public ZKServerMessage {
public:
  DeleteReply(string client, string server, int xid, long long zxid, int error) :
    ZKServerMessage(move(client), move(server), xid, zxid, error) {};

  operator std::string() const { return reply("DeleteReply"); }
};

class SyncReply : public ZKServerMessage {
public:
  SyncReply(string client, string server, int xid, long long zxid, int error, string path) :
    ZKServerMessage(move(client), move(server), xid, zxid, error),
    path_(move(path)) {};

  SyncReply(string client, string server, int xid, long long zxid, int error) :
    ZKServerMessage(move(client), move(server), xid, zxid, error),
    path_(nullptr) {};

  operator std::string() const {
    auto& data = error_ ? "" : path_;
    return reply_data("SyncReply", "path", data);
  }

private:
  string path_;
};

class ExistsReply : public ZKServerMessage {
public:
  ExistsReply(string client, string server, int xid, long long zxid, int error) :
    ZKServerMessage(move(client), move(server), xid, zxid, error), stat_(nullptr) {};

  ExistsReply(string client, string server, int xid, long long zxid, int error,
    unique_ptr<ZnodeStat> stat) :
    ZKServerMessage(move(client), move(server), xid, zxid, error), stat_(move(stat)) {};

  operator std::string() const {
    string stat = "";
    if (!error_ && stat_ != nullptr)
      stat = *stat_.get();
    return reply_stat("ExistsReply", stat);
  }

private:
  unique_ptr<ZnodeStat> stat_;
};

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
  WatchEvent(string client, string server, long long zxid, int error,
    int event_type, int state, string path) :
    ZKServerMessage(move(client), move(server), WATCH_XID, zxid, error),
    event_type_(event_type), state_(state), path_(move(path)) {};

  static std::unique_ptr<WatchEvent> from_payload(string, string, const std::string&, long long, int);
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
    ZKClientMessage(move(client), move(server), CONNECT_XID),
    protocol_(protocol), zxid_(zxid), timeout_(timeout),
    session_(session), passwd_(move(passwd)), readonly_(readonly) {};

  static std::unique_ptr<ConnectRequest> from_payload(string, string, const std::string&);
  int opcode() const { return enumToInt(Opcodes::CONNECT); }

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
    ZKClientMessage(move(client), move(server), PING_XID) {};

  static std::unique_ptr<PingRequest> from_payload(string, string, const string&);
  int opcode() const { return enumToInt(Opcodes::PING); }

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
    ZKClientMessage(move(client), move(server), AUTH_XID),
    type_(type), scheme_(move(scheme)), credential_(move(credential)) {};

  static std::unique_ptr<AuthRequest> from_payload(string, string, const string&);
  int opcode() const { return enumToInt(Opcodes::SETAUTH); }

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
  GetRequest(string client, string server, int xid, string path, bool watch, int opcode) :
    ZKClientMessage(move(client), move(server), xid, move(path), watch) {};

  static std::unique_ptr<GetRequest> from_payload(string, string, const string&);
  operator std::string() const { return req_watch("GetRequest"); }
  int opcode() const { return enumToInt(Opcodes::GETDATA); }
};

class CreateRequest : public ZKClientMessage {
public:
  CreateRequest(string client, string server, int xid, string path,
    bool ephemeral, bool sequence, vector<Acl> acls, int opcode) :
    ZKClientMessage(move(client), move(server), xid, move(path)),
    ephemeral_(ephemeral), sequence_(sequence), acls_(move(acls)), opcode_(opcode) {};

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
  int opcode() const { return opcode_; }

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
  int opcode_;
};

class SetRequest : public ZKClientMessage {
public:
  SetRequest(string client, string server, int xid, string path, int version) :
    ZKClientMessage(move(client), move(server), xid, move(path), version) {};

  operator std::string() const { return req_version("SetRequest"); }
  int opcode() const { return enumToInt(Opcodes::SETDATA); }
};

class DeleteRequest : public ZKClientMessage {
public:
  DeleteRequest(string client, string server, int xid, string path, int version) :
    ZKClientMessage(move(client), move(server), xid, move(path), version) {};

  operator std::string() const { return req_version("DeleteRequest"); }
  int opcode() const { return enumToInt(Opcodes::DELETE); }
};

class GetChildrenRequest : public ZKClientMessage {
public:
  GetChildrenRequest(string client, string server, int xid, string path, bool watch, int opcode) :
    ZKClientMessage(move(client), move(server), xid, move(path), watch), opcode_(opcode) {};

  operator std::string() const {
    const auto name = opcode_ == enumToInt(Opcodes::GETCHILDREN) ? "GetChildrenRequest" : "GetChildren2Request";
    return req_watch(name);
  }
  int opcode() const { return opcode_; }

private:
  int opcode_;
};

class ExistsRequest : public ZKClientMessage {
public:
  ExistsRequest(string client, string server, int xid, string path, bool watch, int opcode) :
    ZKClientMessage(move(client), move(server), xid, move(path), watch) {};

  operator std::string() const { return req_watch("ExistsRequest"); }
  int opcode() const { return enumToInt(Opcodes::EXISTS); }
};

class SyncRequest : public ZKClientMessage {
public:
  SyncRequest(string client, string server, int xid, string path) :
    ZKClientMessage(move(client), move(server), xid, move(path)) {};

  operator std::string() const { return req_path("SyncRequest"); }
  int opcode() const { return enumToInt(Opcodes::SYNC); }
};

} // Zktraffic
