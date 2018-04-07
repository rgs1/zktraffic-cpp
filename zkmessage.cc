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

unique_ptr<ZKClientMessage> ZKClientMessage::from_payload(const string& payload) {
  int length = read_number(payload, 0);
  if (length < 0) {
    return nullptr;
  }

  int xid = read_number(payload, 4);

  if (xid == 0) {
    return ZKConnectRequest::from_payload(payload);
  }

  // handle ping
  // handle get
  // handle create
  // handle set
  // handle setwatches
  
  return nullptr;
}

unique_ptr<ZKServerMessage> ZKServerMessage::from_payload(const string& payload) {
  // handle responses
  // handle watches firing

  return nullptr;
}

unique_ptr<ZKConnectRequest> ZKConnectRequest::from_payload(const string& payload) {
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

  return make_unique<ZKConnectRequest>(protocol,zxid, timeout, session, move(passwd), readonly);
}

}
