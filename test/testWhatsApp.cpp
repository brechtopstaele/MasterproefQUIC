/**
 *  Test for WhatsApp protocol.
 **/
#include "common.h"

TEST(WhatsappTest, Generic) {
<<<<<<< HEAD
    std::vector<uint> protocols;
    getProtocols("./pcaps/whatsapp.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_WHATSAPP], (uint) 134);
=======
  std::vector<uint> protocols;
  getProtocols("./pcaps/whatsapp.pcap", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_WHATSAPP], (uint) 134);
>>>>>>> SoftAtHome/master
}
