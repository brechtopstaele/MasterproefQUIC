/**
 *  Test for Spotify protocol.
 **/
#include "common.h"

TEST(SpotifyTest, Generic) {
<<<<<<< HEAD
    std::vector<uint> protocols;
    getProtocols("./pcaps/spotify.pcapng", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_SPOTIFY], (uint) 437);
=======
  std::vector<uint> protocols;
  getProtocols("./pcaps/spotify.pcapng", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_SPOTIFY], (uint) 437);
>>>>>>> SoftAtHome/master
}
