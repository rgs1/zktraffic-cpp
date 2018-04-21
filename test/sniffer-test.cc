#include <iostream>

#include <unistd.h>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "src/sniffer.h"
#include "src/zkmessage.h"

using namespace std;

TEST(Sniffer, Basic) {
  Zktraffic::Sniffer sniffer{"test/data/basic.pcap", "port 2181", true};
  sniffer.run();

  // wait for packets to be consumed
  while (!sniffer.stopped())
    usleep(500000);

  // connect requests
  auto msg = sniffer.get();
  auto cmsg = dynamic_cast<Zktraffic::ZKClientMessage *>(msg.get());
  EXPECT_EQ(cmsg->opcode(), Zktraffic::enumToInt(Zktraffic::Opcodes::CONNECT));

  // TODO: handle connect reply

  // exists request/reply
  msg = sniffer.get();
  cmsg = dynamic_cast<Zktraffic::ZKClientMessage *>(msg.get());
  EXPECT_EQ(cmsg->opcode(), Zktraffic::enumToInt(Zktraffic::Opcodes::EXISTS));

  msg = sniffer.get();
  EXPECT_EQ(msg.get()->xid(), 1);

  // getchildren request/reply
  msg = sniffer.get();
  cmsg = dynamic_cast<Zktraffic::ZKClientMessage *>(msg.get());
  EXPECT_EQ(cmsg->opcode(), Zktraffic::enumToInt(Zktraffic::Opcodes::GETCHILDREN));

  msg = sniffer.get();
  EXPECT_EQ(msg.get()->xid(), 2);
  auto getchild = dynamic_cast<Zktraffic::GetChildrenReply *>(msg.get());
  EXPECT_THAT(getchild->children(),
    testing::ElementsAre("bar22", "godi10", "godi9", "godi11", "zookeeper", "godi8", "godi7", "foo", "foo2", "godi"));

  // ignore additional exists request/reply
  sniffer.get();
  sniffer.get();

  // get request/reply
  msg = sniffer.get();
  cmsg = dynamic_cast<Zktraffic::ZKClientMessage *>(msg.get());
  EXPECT_EQ(cmsg->opcode(), Zktraffic::enumToInt(Zktraffic::Opcodes::GETDATA));

  msg = sniffer.get();
  EXPECT_EQ(msg.get()->xid(), 4);
  auto getdata = dynamic_cast<Zktraffic::GetReply *>(msg.get());
  EXPECT_THAT(getdata->data(), "feb7");

  // pings reqs/replies
  msg = sniffer.get();
  cmsg = dynamic_cast<Zktraffic::ZKClientMessage *>(msg.get());
  EXPECT_EQ(cmsg->opcode(), Zktraffic::enumToInt(Zktraffic::Opcodes::PING));

  msg = sniffer.get();
  EXPECT_EQ(msg.get()->xid(), Zktraffic::PING_XID);

  msg = sniffer.get();
  cmsg = dynamic_cast<Zktraffic::ZKClientMessage *>(msg.get());
  EXPECT_EQ(cmsg->opcode(), Zktraffic::enumToInt(Zktraffic::Opcodes::PING));

  msg = sniffer.get();
  EXPECT_EQ(msg.get()->xid(), Zktraffic::PING_XID);

  msg = sniffer.get();
  cmsg = dynamic_cast<Zktraffic::ZKClientMessage *>(msg.get());
  EXPECT_EQ(cmsg->opcode(), Zktraffic::enumToInt(Zktraffic::Opcodes::PING));

  msg = sniffer.get();
  EXPECT_EQ(msg.get()->xid(), Zktraffic::PING_XID);

  // ignore additional exists request/reply
  sniffer.get();
  sniffer.get();

  // set req/reply
  msg = sniffer.get();
  cmsg = dynamic_cast<Zktraffic::ZKClientMessage *>(msg.get());
  EXPECT_EQ(cmsg->opcode(), Zktraffic::enumToInt(Zktraffic::Opcodes::SETDATA));

  msg = sniffer.get();
  EXPECT_EQ(msg.get()->xid(), 6);
  auto setdata = dynamic_cast<Zktraffic::SetReply *>(msg.get());
  auto stat = setdata->stat();
  EXPECT_THAT(stat.dataLength(), 12);

  // ignore the rest...
}
