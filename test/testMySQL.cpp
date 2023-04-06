/**
 *  Test for MySQL protocol.
 **/
#include "common.h"

TEST(MySQLTest, Generic) {
<<<<<<< HEAD
    std::vector<uint> protocols;
    getProtocols("./pcaps/mysql.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_MYSQL], (uint) 54);
=======
  std::vector<uint> protocols;
  getProtocols("./pcaps/mysql.pcap", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_MYSQL], (uint) 54);
>>>>>>> SoftAtHome/master
}
