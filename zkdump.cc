#include <iostream>

#include <unistd.h>

#include "sniffer.h"

using namespace std;

int main(int argc, char **argv) {

  if (argc != 2) {
    cout << "Usage: zk-dump <iface>\n";
    return 1;
  }

  Zktraffic::Sniffer sniffer{argv[1], "port 2181"};

  sniffer.run();

  while (1) {
    auto message = sniffer.get();
    cout << (string)*message << "\n";
  }

  return 0;
}
