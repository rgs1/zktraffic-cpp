#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>

#include "pcap.h"

#include "zkmessage.h"

using namespace std;

namespace Zktraffic {

class Sniffer {
public:
  Sniffer(const std::string iface, const std::string filter)
    : iface_(iface), filter_(filter), running_(false) {
  }
  void run();
  void stop();
  std::unique_ptr<ZKMessage> get() {
      unique_lock<mutex> guard(mutex_);
      while (queue_.empty())
	  cv_.wait(guard);

      auto rv = std::move(queue_.front());
      queue_.pop();
      return rv;
  }

private:
  void packetHandler(const struct pcap_pkthdr* header,  const u_char *packet);
  std::string iface_;
  std::string filter_;
  volatile bool running_;
  thread *runner_;
  queue<unique_ptr<ZKMessage>> queue_;
  mutex mutex_;
  condition_variable cv_;
};

}

