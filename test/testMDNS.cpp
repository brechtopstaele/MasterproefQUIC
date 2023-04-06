/**
 *  Test for MDNS protocol.
 **/
#include "common.h"

TEST(MDNSTest, Generic) {
<<<<<<< HEAD
    std::vector<uint> protocols;
    getProtocols("./pcaps/dropbox.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_MDNS], (uint) 16);
=======
  std::vector<uint> protocols;
  getProtocols("./pcaps/dropbox.pcap", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_MDNS], (uint) 16);
>>>>>>> SoftAtHome/master
}
