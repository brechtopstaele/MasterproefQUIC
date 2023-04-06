/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(SMTPTest, Generic) {
<<<<<<< HEAD
    std::vector<uint> protocols;
    getProtocols("./pcaps/smtp.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_SMTP], (uint) 47);
=======
  std::vector<uint> protocols;
  getProtocols("./pcaps/smtp.pcap", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_SMTP], (uint) 47);
>>>>>>> SoftAtHome/master
}
