#include <iostream>
#include <memory>
#include <string>

#include <pcap.h>

#include "tcp_packet.h"
#include "sniffer.h"

using namespace std;

namespace Zktraffic {

void Sniffer::run() {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  struct bpf_program fp;

  handle = pcap_open_live(iface_.c_str(), 8192, 1, 1000, errbuf);
  if (handle == NULL) {
    cout << "couldn't sniff (iface: " << iface_ << "): " << errbuf << "\n";
    return;
  }

  // cout << "datalink type: " << pcap_datalink(handle) << "\n";

  if (pcap_compile(handle, &fp, filter_.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
    cout << "couldn't compile the filter (iface: " << iface_ << ")\n";
    return;
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    cout << "couldn't set the filter (iface: " << iface_ << ")\n";
    return;
  }

  cout << "running (iface: " << iface_ << ")\n";
  running_ = true;

  runner_ = new thread([this, handle]() {
      const u_char *packet;
      struct pcap_pkthdr header;

      while (running_) {
	packet = pcap_next(handle, &header);
	packetHandler(&header, packet);
      }

      pcap_close(handle);
    });

  // TODO: when is join() called?
}

void Sniffer::stop() {
  running_ = false;
  runner_->join();
}

void Sniffer::packetHandler(const struct pcap_pkthdr* header,  const u_char *packet) {
  auto tcpp = TcpPacket::from_pcap(header, packet);
  if (tcpp == nullptr) {
    return;
  }

  // extract zk requests/replies
  unique_ptr<ZKMessage> message;
  if (tcpp->dst_port() == 2181) {
    auto client = tcpp->src();
    auto server = tcpp->dst();
    message = ZKClientMessage::from_payload(move(client), move(server), tcpp->payload());
  } else {
    auto server = tcpp->src();
    auto client = tcpp->dst();
    message = ZKServerMessage::from_payload(move(client), move(server), tcpp->payload());
  }

  // add to the queue
  if (message != nullptr) {
    unique_lock<mutex> lock(mutex_);
    queue_.push(move(message));
    lock.unlock();
    cv_.notify_one();
  }
}

}
