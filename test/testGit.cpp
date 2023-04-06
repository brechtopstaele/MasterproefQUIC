/**
 *  Test for Git protocol.
 **/
#include "common.h"

TEST(DropboxTest, Generic) {
<<<<<<< HEAD
    std::vector<uint> protocols;
    getProtocols("./pcaps/git.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_GIT], (uint) 87);
=======
  std::vector<uint> protocols;
  getProtocols("./pcaps/git.pcap", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_GIT], (uint) 87);
>>>>>>> SoftAtHome/master
}
