/**
 *  Test for IMAP protocol.
 **/
#include "common.h"

TEST(IMAPTest, Generic) {
<<<<<<< HEAD
    std::vector<uint> protocols;
    getProtocols("./pcaps/imap.cap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_IMAP], (uint) 2);

    getProtocols("./pcaps/imap-ssl.pcapng", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_IMAP], (uint) 34);
=======
  std::vector<uint> protocols;
  getProtocols("./pcaps/imap.cap", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_IMAP], (uint) 2);

  getProtocols("./pcaps/imap-ssl.pcapng", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_IMAP], (uint) 34);
>>>>>>> SoftAtHome/master
}
