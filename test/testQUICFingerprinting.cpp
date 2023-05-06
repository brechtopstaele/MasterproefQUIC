/**
 *  Test for QUIC protocol fingerprinting.
 **/
#include "common.h"

#ifdef HAVE_OPENSSL

static void checkJA3(const char *pcap, const char *ja3) {
  std::vector<uint> protocols;
  pfwl_state_t *state = pfwl_init();
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_JA3);

  bool foundja3 = false;

  getProtocols(pcap, protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r) {
    pfwl_string_t field;
    if (status >= PFWL_STATUS_OK && r.l7.protocol == PFWL_PROTO_L7_QUIC5) {
      if (!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_JA3, &field)) {
        EXPECT_EQ(strncmp((const char *) field.value, ja3, field.length), 0);
        foundja3 = true;
      }
    }
  });
  EXPECT_TRUE(foundja3);

  pfwl_terminate(state);
}

TEST(QUICTest, JA3) {
  checkJA3("./test/pcaps/quic-draft29.pcap", "dc45c41224f2d966d2c8378bc3e1f0d2");
  checkJA3("./test/pcaps/quic-1-double.pcap", "b719940c5ab9a3373cb4475d8143ff88");
}

static void checkJOY(const char *pcap, const char *joy) {
  std::vector<uint> protocols;
  pfwl_state_t *state = pfwl_init();
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_JOY);

  bool foundjoy = false;

  getProtocols(pcap, protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r) {
    pfwl_string_t field;
    if (status >= PFWL_STATUS_OK && r.l7.protocol == PFWL_PROTO_L7_QUIC5) {
      if (!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_JOY, &field)) {
        EXPECT_EQ(strncmp((const char *) field.value, joy, field.length), 0);
        foundjoy = true;
      }
    }
  });
  EXPECT_TRUE(foundjoy);

  pfwl_terminate(state);
}

// TODO: get a working Joy verification
// TEST(QUICTest, JOY) {
//   checkJOY("./pcaps/quic-draft29.pcap", "dc45c41224f2d966d2c8378bc3e1f0d2");
//   checkJOY("./pcaps/quic-1-double.pcap", "b719940c5ab9a3373cb4475d8143ff88");
// }

static void checkNPF(const char *pcap, const char *npf) {
  std::vector<uint> protocols;
  pfwl_state_t *state = pfwl_init();
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_NPF);

  bool foundnpf = false;

  getProtocols(pcap, protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r) {
    pfwl_string_t field;
    if (status >= PFWL_STATUS_OK && r.l7.protocol == PFWL_PROTO_L7_QUIC5) {
      if (!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_NPF, &field)) {
        EXPECT_EQ(strncmp((const char *) field.value, npf, field.length), 0);
        foundnpf = true;
      }
    }
  });
  EXPECT_TRUE(foundnpf);

  pfwl_terminate(state);
}

TEST(QUICTest, NPF) {
  checkNPF("./test/pcaps/quic-draft29.pcap", "quic/(ff00001d)(0303)(130113021303)[(0000)(000a00080006001d00170018)(000d00140012040308040401050308050501080606010201)(0010000800060568332d3239)(0029)(002a)(002b0003020304)(002d00020101)(0033)((ffa5)[(01)(03)(04)(05)(06)(07)(08)(09)(0f)(1b)(20)(7127)(7129)(712b)(80004752)])]");
  checkNPF("./test/pcaps/quic-1-double.pcap", "quic/(00000001)(0303)(130113031302)[(0000)(000500050100000000)(000a00140012001d00170018001901000101010201030104)(000d0018001604030503060302030804080508060401050106010201)(001000050003026833)(0015)(0017)(001c00024001)(0022)(002b0003020304)(002d00020101)(0033)((0039)[(01)(04)(05)(06)(07)(08)(09)(0b)(0c)(0e)(0f)(1b)(20)(6ab2)(80ff73db)])(ff01)]");
}
#endif
