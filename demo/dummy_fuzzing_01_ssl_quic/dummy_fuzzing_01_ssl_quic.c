/*
 * ssl_extraction.c
 *
 * Given a .pcap file, extracts the SSL certificate contained in it.
 *
 * Created on: 19/09/2012
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * =========================================================================
 */

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <peafowl/peafowl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s pcap_file\n", argv[0]);
    return -1;
  }
  char *pcap_filename = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  pfwl_state_t *state = pfwl_init();
  pcap_t *handle = pcap_open_offline(pcap_filename, errbuf);

  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", pcap_filename, errbuf);
    return (2);
  }

  const u_char *packet;
  struct pcap_pkthdr header;

  pfwl_protocol_l7_disable_all(state);
  pfwl_protocol_l7_enable(state, PFWL_PROTO_L7_SSL);
  pfwl_protocol_l7_enable(state, PFWL_PROTO_L7_QUIC);
  pfwl_protocol_l7_enable(state, PFWL_PROTO_L7_QUIC5);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_SSL_JA3);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_SSL_HANDSHAKE_TYPE);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_VERSION);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_SNI);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_UAID);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_JA3);

  pfwl_protocol_l2_t dlt = pfwl_convert_pcap_dlt(pcap_datalink(handle));
  while ((packet = pcap_next(handle, &header)) != NULL) {
    pfwl_dissection_info_t r;
    if (pfwl_dissect_from_L2(state, packet, header.caplen, time(NULL), dlt, &r) >= PFWL_STATUS_OK) {
      pfwl_string_t field;
      if (r.l7.protocol == PFWL_PROTO_L7_SSL &&
          !pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_JA3, &field)) {
        int64_t htype;
        pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_HANDSHAKE_TYPE, &htype);
        if (htype == 0x01) {
          printf("JA3: %.*s\n", (int) field.length, field.value);
        } else if (htype == 0x02) {
          printf("JA3S: %.*s\n", (int) field.length, field.value);
        }
      }
    }
  }
  pcap_close(handle);
  pfwl_terminate(state);
  return 0;
}
