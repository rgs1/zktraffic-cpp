#include "zkmessage.h"

#include <iostream>
#include <memory>
#include <string>

using namespace std;

namespace Zktraffic {
namespace {

#define CHECK_LENGTH(P, MINL)                       \
  if (read_number(P, 0) < MINL) return nullptr

// https://commandcenter.blogspot.fr/2012/04/byte-order-fallacy.html
int read_number(const string& data, unsigned int offset) {
  if (offset + 4 > data.length())
    return -1;

  auto n = data.substr(offset, 4);
  int number = ((unsigned char)n[3]<<0) | \
    ((unsigned char)n[2]<<8) | \
    ((unsigned char)n[1]<<16) | \
    ((unsigned char)n[0]<<24);

  return number;
}

string to_bits(char c) {
  stringstream ss;

  for (int i =7; i >= 0; i-- ) {
    int bit = c & (1 << i) ? 1 : 0;
    ss << bit;
  }

  return ss.str();
}

void dump(const string& payload) {
  for (unsigned int i=0; i<payload.length(); i++)
    cout << "payload[" << i << "] = " << to_bits(payload[i]) << "\n";
}

long long read_long(const string& data, int offset) {
  auto n = data.substr(offset, 8);

  // careful when casting, watch out for 2's complement
  unsigned long long number = ((unsigned long long)(unsigned char)n[7]<<0) |	\
    ((unsigned long long)(unsigned char)n[6]<<8) | \
    ((unsigned long long)(unsigned char)n[5]<<16) | \
    ((unsigned long long)(unsigned char)n[4]<<24) | \
    ((unsigned long long)(unsigned char)n[3]<<32) | \
    ((unsigned long long)(unsigned char)n[2]<<40) | \
    ((unsigned long long)(unsigned char)n[1]<<48) | \
    ((unsigned long long)(unsigned char)n[0]<<56);

  return number;
}

bool read_bool(const string& data, unsigned int offset) {
  if (offset >= data.length()) {
    return false;
  }
  return (bool)(data[offset] & 255);
}

string read_buffer(const string& data, int offset, int maxlen=1048576) {
  int length = read_number(data, offset);
  return data.substr(offset + 4, length);
}

pair<vector<Acl>, int> read_acls(const string& payload, int offset) {
  vector<Acl> acls{};
  int count = read_number(payload, offset);

  offset += 4;

  if (count < 0)
    return pair<vector<Acl>, int>{acls, offset};

  for (int i=0; i<count; i++) {
    int perms = read_number(payload, offset);
    offset += 4;
    string scheme = read_buffer(payload, offset);
    offset += 4 + scheme.length();
    string credential = read_buffer(payload, offset);
    offset += 4 + credential.length();

    auto acl = Acl(perms, move(scheme), move(credential));
    acls.push_back(move(acl));
  }

  return pair<vector<Acl>, int>{acls, offset};
}

template <typename T>
unique_ptr<T> from_payload_path_watch(string client, string server, const string& payload) {
  // xid(int) + opcode(int) + path(int + str) + watch(bool)
  CHECK_LENGTH(payload, 14);

  int xid = read_number(payload, 4);
  string path = read_buffer(payload, 12);
  bool watch = read_bool(payload, 12 + 4 + path.length());

  return make_unique<T>(move(client), move(server), xid, move(path), watch);
}

template <typename T>
unique_ptr<T> from_payload_path_data_version(string client, string server, const string& payload) {
  // xid(int) + opcode(int) + path(int + str) + data(str) + version(int)
  CHECK_LENGTH(payload, 22);

  int xid = read_number(payload, 4);
  string path = read_buffer(payload, 12);
  int data_len = read_number(payload, 16 + path.length());
  int version = read_number(payload, 20 + path.length() + data_len);

  return make_unique<T>(move(client), move(server), xid, move(path), version);
}

template <typename T>
unique_ptr<T> from_payload_path_version(string client, string server, const string& payload) {
  // xid(int) + opcode(int) + path(int + str) + version(int)
  CHECK_LENGTH(payload, 17);

  int xid = read_number(payload, 4);
  string path = read_buffer(payload, 12);
  int version = read_number(payload, 16 + path.length());

  return make_unique<T>(move(client), move(server), xid, move(path), version);
}

template <typename T>
unique_ptr<T> from_payload_path(string client, string server, const string& payload) {
  // xid(int) + opcode(int) + path(int + str)
  CHECK_LENGTH(payload, 17);

  int xid = read_number(payload, 4);
  string path = read_buffer(payload, 12);

  return make_unique<T>(move(client), move(server), xid, move(path));
}

unique_ptr<ZnodeStat> read_stat(const string& payload, unsigned int offset) {
  long long czxid = read_long(payload, offset);
  long long mzxid = read_long(payload, offset + 8);
  long long ctime = read_long(payload, offset + 16);
  long long mtime = read_long(payload, offset + 24);
  int version = read_number(payload, offset + 32);
  int cversion = read_number(payload, offset + 36);
  int aversion = read_number(payload, offset + 40);
  long long ephemeralOwner = read_long(payload, offset + 44);
  int dataLength = read_number(payload, offset + 52);
  int numChildren = read_number(payload, offset + 56);
  long long pzxid = read_long(payload, offset + 60);

  return make_unique<ZnodeStat>(czxid, mzxid, ctime, mtime,
    version, cversion, aversion, ephemeralOwner, dataLength, numChildren, pzxid);
}

template <typename T>
unique_ptr<T> from_reply_payload_data_stat(string client, string server, int xid, long zxid, int error, const string& payload)
{
  // xid(int) + zxid(long) + error(int) + data(int + str) + stat(68)
  CHECK_LENGTH(payload, 16);

  if (error) {
    return make_unique<T>(move(client), move(server), xid, zxid, error);
  }

  CHECK_LENGTH(payload, 88);

  auto data = read_buffer(payload, 20);
  auto stat = read_stat(payload, 24 + data.length());

  return make_unique<T>(move(client), move(server), xid, zxid, error, move(data), move(stat));
}

} // namespace

unique_ptr<ZKClientMessage> ZKClientMessage::from_payload(string client,
  string server, const string& payload) {
  CHECK_LENGTH(payload, 8);

  // "special" requests
  int xid = read_number(payload, 4);
  switch (xid) {
  case CONNECT_XID:
    return ConnectRequest::from_payload(move(client), move(server), payload);
  case PING_XID:
    return make_unique<PingRequest>(move(client), move(server));
  case AUTH_XID:
    return AuthRequest::from_payload(move(client), move(server), payload);
  default:
    break;
  }

  // "regular" requests
  int opcode = read_number(payload, 8);
  switch (opcode) {
  case enumToInt(Opcodes::GETDATA):
    return from_payload_path_watch<GetRequest>(move(client), move(server), payload);
  case enumToInt(Opcodes::CREATE):
  case enumToInt(Opcodes::CREATE2):
    return CreateRequest::from_payload(move(client), move(server), payload);
  case enumToInt(Opcodes::SETDATA):
    return from_payload_path_data_version<SetRequest>(move(client), move(server), payload);
  case enumToInt(Opcodes::GETCHILDREN):
  case enumToInt(Opcodes::GETCHILDREN2):
    return from_payload_path_watch<GetChildrenRequest>(move(client), move(server), payload);
  case enumToInt(Opcodes::DELETE):
    return from_payload_path_version<DeleteRequest>(move(client), move(server), payload);
  case enumToInt(Opcodes::SYNC):
    return from_payload_path<SyncRequest>(move(client), move(server), payload);
  case enumToInt(Opcodes::EXISTS):
    return from_payload_path_watch<ExistsRequest>(move(client), move(server), payload);
  default:
    break;
  }
  
  return nullptr;
}

unique_ptr<ZKServerMessage> ZKServerMessage::from_payload(string client, string server,
  const string& payload, const unordered_map<int, int>& requests) {
  CHECK_LENGTH(payload, 16);

  // "special" server messages
  int xid = read_number(payload, 4);
  long long zxid = read_long(payload, 8);
  int error = read_number(payload, 16);

  switch (xid) {
  case PING_XID:
    return make_unique<PingReply>(move(client), move(server), zxid, error);
  case WATCH_XID:
    return WatchEvent::from_payload(move(client), move(server), payload, zxid, error);
  default:
    break;
  }

  // handle responses from seen requests
  auto opcode = requests.find(xid);
  if (opcode == requests.end())
    return nullptr;

  switch (opcode->second) {
  case enumToInt(Opcodes::GETDATA):
    return from_reply_payload_data_stat<GetReply>(move(client), move(server), xid, zxid, error, payload);
  case enumToInt(Opcodes::CREATE):
    break;
  case enumToInt(Opcodes::CREATE2):
    break;
  case enumToInt(Opcodes::SETDATA):
    break;
  case enumToInt(Opcodes::GETCHILDREN):
    break;
  case enumToInt(Opcodes::GETCHILDREN2):
    break;
  case enumToInt(Opcodes::DELETE):
    break;
  case enumToInt(Opcodes::SYNC):
    break;
  case enumToInt(Opcodes::EXISTS):
    break;
  default:
    break;
  }

  return nullptr;
}

unique_ptr<WatchEvent> WatchEvent::from_payload(string client, string server, const string& payload,
  long long zxid, int error) {
  // reply_header(16) + event_type(int) + state(int) + path(int + str)
  CHECK_LENGTH(payload, 29);

  int event_type = read_number(payload, 20);
  int state = read_number(payload, 24);
  string path = read_buffer(payload, 28);

  return make_unique<WatchEvent>(move(client), move(server), zxid, error, event_type, state, path);
}

unique_ptr<ConnectRequest> ConnectRequest::from_payload(string client, string server, const string& payload) {
  // proto(int) + zxid(long) + timeout(int) + session(long) + passwd(int + str) + readonly(bool)
  CHECK_LENGTH(payload, 29);

  int protocol = read_number(payload, 4);
  long long zxid = read_long(payload, 8);
  int timeout = read_number(payload, 16);
  long long session = read_long(payload, 20);
  string passwd = read_buffer(payload, 28);
  bool readonly = read_bool(payload, 28 + 4 + passwd.length());

  return make_unique<ConnectRequest>(move(client), move(server),
    protocol, zxid, timeout, session, move(passwd), readonly);
}

unique_ptr<AuthRequest> AuthRequest::from_payload(string client, string server, const string& payload) {
  // xid(int) + opcode(int) + type(int) + scheme(int + str) + cred(int + auth)
  CHECK_LENGTH(payload, 20);

  int type = read_number(payload, 12);
  string scheme = read_buffer(payload, 16);
  string cred = read_buffer(payload, 20 + scheme.length());

  return make_unique<AuthRequest>(move(client), move(server), type, move(scheme), move(cred));
}

unique_ptr<CreateRequest> CreateRequest::from_payload(string client, string server, const string& payload) {
  // xid(int) + opcode(int) + path(int + str) + data(str) + acls(vector) + ephemeral(bool) + sequence(bool)
  CHECK_LENGTH(payload, 25);

  int xid = read_number(payload, 4);
  string path = read_buffer(payload, 12);
  int data_len = read_number(payload, 16 + path.length());
  auto acls_rv = read_acls(payload, 20 + path.length() + data_len);
  auto acls = acls_rv.first;
  int flags = read_number(payload, acls_rv.second);
  bool ephemeral = (flags & 0x1) == 1;
  bool sequence = (flags & 0x2) == 2;

  return make_unique<CreateRequest>(move(client), move(server), xid, move(path),
    ephemeral, sequence, move(acls));
}

}
