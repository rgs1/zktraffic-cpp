#include "zkmessage.h"

#include <iostream>
#include <memory>
#include <string>

using namespace std;

namespace Zktraffic {

// https://commandcenter.blogspot.fr/2012/04/byte-order-fallacy.html
int read_number(const string& data, int offset) {
  auto n = data.substr(offset, 4);
  int number = ((unsigned char)n[3]<<0) | \
    ((unsigned char)n[2]<<8) | \
    ((unsigned char)n[1]<<16) | \
    ((unsigned char)n[0]<<24);

  return number;
}

int read_long(const string& data, int offset) {
  auto n = data.substr(offset, 8);
  long long number = ((unsigned char)n[7]<<0) | \
    ((unsigned char)n[6]<<8) | \
    ((unsigned char)n[5]<<16) | \
    ((unsigned char)n[4]<<24) | \
    ((unsigned char)n[3]<<32) | \
    ((unsigned char)n[2]<<40) | \
    ((unsigned char)n[1]<<48) | \
    ((unsigned char)n[0]<<56);

  return number;
}

bool read_bool(const string& data, unsigned int offset) {
  if (offset >= data.length()) {
    return false;
  }
  return (bool)(data[offset] & 255);
}

string read_buffer(const string& data, int offset) {
  int length = read_number(data, offset);
  return data.substr(offset + 4, length);
}

const int CONNECT_XID = 0;
const int WATCH_XID = -1;
const int PING_XID = -2;
const int AUTH_XID = -4;
const int SET_WATCHES_XID = -8;

unique_ptr<ZKClientMessage> ZKClientMessage::from_payload(string client,
  string server, const string& payload) {
  int length = read_number(payload, 0);
  if (length < 0) {
    return nullptr;
  }

  int xid = read_number(payload, 4);
  switch (xid) {
  case CONNECT_XID:
    return ConnectRequest::from_payload(move(client), move(server), payload);
  case PING_XID:
    return PingRequest::from_payload(move(client), move(server), payload);
  case AUTH_XID:
    return AuthRequest::from_payload(move(client), move(server), payload);
  default:
    break;
  }

  // handle get
  // handle create
  // handle set
  // handle setwatches
  
  return nullptr;
}

unique_ptr<ZKServerMessage> ZKServerMessage::from_payload(string client, string server, const string& payload) {
  // handle responses
  // handle watches firing

  return nullptr;
}

unique_ptr<ConnectRequest> ConnectRequest::from_payload(string client, string server, const string& payload) {
  int length = read_number(payload, 0);
  if (length < 32) {
    return nullptr;
  }

  int protocol = read_number(payload, 4);
  long long zxid = read_long(payload, 8);
  int timeout = read_number(payload, 16);
  long long session = read_long(payload, 20);
  string passwd = read_buffer(payload, 28);
  bool readonly = read_bool(payload, 28 + 4 + passwd.length());

  return make_unique<ConnectRequest>(move(client), move(server),
    protocol,zxid, timeout, session, move(passwd), readonly);
}

unique_ptr<PingRequest> PingRequest::from_payload(string client, string server, const string& payload) {
  return make_unique<PingRequest>(move(client), move(server));
}

void dump_payload(const string& payload) {
  for (int i=0; i<payload.length(); i++)
    cout << "payload[" << i << "] = " << payload[i] << "\n";
}

unique_ptr<AuthRequest> AuthRequest::from_payload(string client, string server, const string& payload) {
  int length = read_number(payload, 0);
  if (length < 24) {  // length(int) + xid(int) + opcode(int) + type(int) + scheme(int + str) + cred(int + auth)
    return nullptr;
  }

  int opcode = read_number(payload, 8);
  int type = read_number(payload, 12);
  string scheme = read_buffer(payload, 16);
  string cred = read_buffer(payload, 20 + scheme.length());

  return make_unique<AuthRequest>(move(client), move(server),
    type, move(scheme), move(cred));
}

}
