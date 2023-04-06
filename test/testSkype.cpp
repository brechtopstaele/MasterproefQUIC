/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

TEST(SkypeTest, Generic) {
<<<<<<< HEAD
    std::vector<uint> protocols;
    getProtocols("./pcaps/skype-irc.cap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_SKYPE], (uint) 326);
=======
  std::vector<uint> protocols;
  getProtocols("./pcaps/skype-irc.cap", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_SKYPE], (uint) 326);
>>>>>>> SoftAtHome/master
}
