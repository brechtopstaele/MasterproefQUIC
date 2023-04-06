/**
 *  Test for Bitcoin protocol.
 **/
#include "common.h"

TEST(BitcoinTest, Generic) {
<<<<<<< HEAD
    std::vector<uint> protocols;
    getProtocols("./pcaps/bitcoin.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_BITCOIN], (uint) 285);
=======
  std::vector<uint> protocols;
  getProtocols("./pcaps/bitcoin.pcap", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_BITCOIN], (uint) 285);
>>>>>>> SoftAtHome/master
}
