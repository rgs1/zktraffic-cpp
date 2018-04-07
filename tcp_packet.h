#pragma once

#include <memory>
#include <sstream>
#include <string>

#include "pcap.h"

using namespace std;

namespace Zktraffic {

class TcpPacket {
public:
  TcpPacket(
      int sport, int dport, const char *src_ip, const char *dst_ip,
      const char *payload, int payload_len) : src_port_(sport), dst_port_(dport),
	src_ip_(src_ip), dst_ip_(dst_ip),
	payload_(payload, payload_len) {};
  static std::unique_ptr<TcpPacket> from_pcap(const struct pcap_pkthdr*,  const u_char *);
  int src_port() const { return src_port_; }
  int dst_port() const { return dst_port_; }
  const std::string& src_ip() const { return src_ip_; }
  const std::string& dst_ip() const { return dst_ip_; }
  const std::string& payload() const { return payload_; }
  string src() const {
    stringstream ss;
    ss << src_ip_ << ":" << src_port_;
    return move(ss.str());
  }

  string dst() {
    stringstream ss;
    ss << dst_ip_ << ":" << dst_port_;
    return move(ss.str());
  }

private:
  int src_port_;
  int dst_port_;
  std::string src_ip_;
  std::string dst_ip_;
  std::string payload_;
};

}
