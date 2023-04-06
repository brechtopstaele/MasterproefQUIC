/**
 *  Test for Dropbox protocol.
 **/
#include "common.h"

TEST(DropboxTest, Generic) {
<<<<<<< HEAD
    std::vector<uint> protocols;
    getProtocols("./pcaps/dropbox.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_DROPBOX], (uint) 812);
    getProtocols("./pcaps/dropbox_2.pcapng", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_DROPBOX], (uint) 12);
=======
  std::vector<uint> protocols;
  getProtocols("./pcaps/dropbox.pcap", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_DROPBOX], (uint) 812);
  getProtocols("./pcaps/dropbox_2.pcapng", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_DROPBOX], (uint) 12);
>>>>>>> SoftAtHome/master
}
