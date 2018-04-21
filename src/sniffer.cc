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

  stopped_ = false;

  if (from_file_)
    handle = pcap_open_offline(iface_.c_str(), errbuf);
  else
    handle = pcap_open_live(iface_.c_str(), 8192, 1, 1000, errbuf);

  if (handle == NULL) {
    if (from_file_)
      cout << "couldn't sniff (file: " << iface_ << "): " << errbuf << "\n";
    else
      cout << "couldn't sniff (iface: " << iface_ << "): " << errbuf << "\n";
    stopped_ = true;
    return;
  }

  if (pcap_compile(handle, &fp, filter_.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
    cout << "couldn't compile the filter (iface: " << iface_ << ")\n";
    stopped_ = true;
    return;
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    cout << "couldn't set the filter (iface: " << iface_ << ")\n";
    stopped_ = true;
    return;
  }

  if (from_file_)
    cout << "running (file: " << iface_ << ")\n";
  else
    cout << "running (iface: " << iface_ << ")\n";

  running_ = true;
  runner_ = new thread([this, handle]() {
      const u_char *packet;
      struct pcap_pkthdr header;

      while (running_) {
	packet = pcap_next(handle, &header);
	if (packet == nullptr)
	  break;
	packetHandler(&header, packet);
      }
      cout << "exiting sniffing loop...\n";
      pcap_close(handle);
      stopped_ = true;
    });
  runner_->detach();
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
    if (message != nullptr) {
      auto client_msg = dynamic_cast<ZKClientMessage *>(message.get());
      // TODO: check for max msgs
      if (client_msg->xid() != PING_XID)
	requests_.emplace(client_msg->xid(), client_msg->opcode());
    }
  } else {
    auto server = tcpp->src();
    auto client = tcpp->dst();
    message = ZKServerMessage::from_payload(move(client), move(server), tcpp->payload(), requests_);
    if (message != nullptr && message->xid() != PING_XID)
      requests_.erase(message->xid());
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
