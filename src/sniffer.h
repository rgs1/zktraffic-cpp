#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>

#include "pcap.h"

#include "zkmessage.h"

using namespace std;

namespace Zktraffic {

class Sniffer {
public:
  Sniffer(const std::string iface, const std::string filter, bool from_file=false)
      : iface_(iface), filter_(filter), from_file_(from_file), running_(false),
	stopped_(false) {}
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
  bool empty() {
      unique_lock<mutex> guard(mutex_);
      return queue_.empty();
  }
  bool stopped() const { return stopped_; }

private:
  void packetHandler(const struct pcap_pkthdr* header,  const u_char *packet);
  std::string iface_;
  std::string filter_;
  bool from_file_;
  volatile bool running_;
  volatile bool stopped_;
  thread *runner_;
  queue<unique_ptr<ZKMessage>> queue_;
  mutex mutex_;
  condition_variable cv_;
  unordered_map<int, int> requests_;  // TODO: protect with lock
};

}

