/**
 *  Test for Hangout protocol.
 **/
#include "common.h"

TEST(HangoutTest, Generic) {
<<<<<<< HEAD
    std::vector<uint> protocols;
    getProtocols("./pcaps/hangout.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HANGOUT], (uint) 100);
=======
  std::vector<uint> protocols;
  getProtocols("./pcaps/hangout.pcap", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_HANGOUT], (uint) 100);
>>>>>>> SoftAtHome/master
}
