/*
 * peafowl.c
 *
 * Created on: 19/09/2012
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
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

#include <peafowl/config.h>
#include <peafowl/flow_table.h>
#include <peafowl/hash_functions.h>
#include <peafowl/inspectors/inspectors.h>
#include <peafowl/ipv4_reassembly.h>
#include <peafowl/ipv6_reassembly.h>
#include <peafowl/peafowl.h>
#include <peafowl/tcp_stream_management.h>
#include <peafowl/utils.h>

<<<<<<< HEAD
=======
#include "tags.h"

>>>>>>> SoftAtHome/master
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

<<<<<<< HEAD
#define debug_print(fmt, ...)                                                  \
  do {                                                                         \
    if (PFWL_DEBUG)                                                            \
      fprintf(stderr, fmt, __VA_ARGS__);                                       \
  } while (0)

uint8_t pfwl_set_expected_flows(pfwl_state_t *state, uint32_t flows,
                                pfwl_flows_strategy_t strategy) {
=======
#define debug_print(fmt, ...)            \
  do {                                   \
    if (PFWL_DEBUG)                      \
      fprintf(stderr, fmt, __VA_ARGS__); \
  } while (0)

uint8_t pfwl_set_expected_flows(pfwl_state_t *state, uint32_t flows, pfwl_flows_strategy_t strategy) {
>>>>>>> SoftAtHome/master
  if (state) {
    assert(state->flow_table);
    pfwl_flow_table_delete(state->flow_table, state->ts_unit);
    state->flow_table = pfwl_flow_table_create(flows, strategy, 1);
    return 0;
<<<<<<< HEAD
  }else{
=======
  } else {
>>>>>>> SoftAtHome/master
    return 1;
  }
}

<<<<<<< HEAD
pfwl_state_t *pfwl_init_stateful_num_partitions(uint32_t expected_flows,
                                                uint8_t strict,
=======
pfwl_state_t *pfwl_init_stateful_num_partitions(uint32_t expected_flows, uint8_t strict,
>>>>>>> SoftAtHome/master
                                                uint16_t num_table_partitions) {
  pfwl_state_t *state = (pfwl_state_t *) malloc(sizeof(pfwl_state_t));

  assert(state);

  bzero(state, sizeof(pfwl_state_t));

#if PFWL_FLOW_TABLE_USE_MEMORY_POOL
<<<<<<< HEAD
  state->db4 = pfwl_flow_table_create_v4(
      size_v4, max_active_v4_flows, num_table_partitions,
      PFWL_FLOW_TABLE_MEMORY_POOL_DEFAULT_SIZE_v4);
  state->db6 = pfwl_flow_table_create_v6(
      size_v6, max_active_v6_flows, num_table_partitions,
      PFWL_FLOW_TABLE_MEMORY_POOL_DEFAULT_SIZE_v6);
#else
  state->flow_table =
      pfwl_flow_table_create(expected_flows, strict, num_table_partitions);
=======
  state->db4 = pfwl_flow_table_create_v4(size_v4, max_active_v4_flows, num_table_partitions,
                                         PFWL_FLOW_TABLE_MEMORY_POOL_DEFAULT_SIZE_v4);
  state->db6 = pfwl_flow_table_create_v6(size_v6, max_active_v6_flows, num_table_partitions,
                                         PFWL_FLOW_TABLE_MEMORY_POOL_DEFAULT_SIZE_v6);
#else
  state->flow_table = pfwl_flow_table_create(expected_flows, strict, num_table_partitions);
>>>>>>> SoftAtHome/master
#endif
  // Must be called before pfwl_protocol_l7_enable_all
  memset(state->fields_to_extract, 0, sizeof(state->fields_to_extract));
  memset(state->fields_to_extract_num, 0, sizeof(state->fields_to_extract_num));
  memset(state->fields_support, 0, sizeof(state->fields_support));
  memset(state->fields_support_num, 0, sizeof(state->fields_support_num));
<<<<<<< HEAD
  for(size_t i = 0; i < PFWL_PROTO_L7_NUM; i++){
=======
  for (size_t i = 0; i < PFWL_PROTO_L7_NUM; i++) {
>>>>>>> SoftAtHome/master
    state->protocol_dependencies[i][0] = PFWL_PROTO_L7_NUM;
  }

  pfwl_set_max_trials(state, PFWL_DEFAULT_MAX_TRIALS_PER_FLOW);
  pfwl_protocol_l7_enable_all(state);

<<<<<<< HEAD
  pfwl_defragmentation_enable_ipv4(state,
                                   PFWL_IPv4_FRAGMENTATION_DEFAULT_TABLE_SIZE);
  pfwl_defragmentation_enable_ipv6(state,
                                   PFWL_IPv6_FRAGMENTATION_DEFAULT_TABLE_SIZE);
=======
  pfwl_defragmentation_enable_ipv4(state, PFWL_IPv4_FRAGMENTATION_DEFAULT_TABLE_SIZE);
  pfwl_defragmentation_enable_ipv6(state, PFWL_IPv6_FRAGMENTATION_DEFAULT_TABLE_SIZE);
>>>>>>> SoftAtHome/master

  pfwl_tcp_reordering_enable(state);

  state->l7_skip = NULL;
  state->ts_unit = PFWL_TIMESTAMP_UNIT_SECONDS;
  return state;
}

pfwl_state_t *pfwl_init() {
  return pfwl_init_stateful_num_partitions(PFWL_DEFAULT_EXPECTED_FLOWS, 0, 1);
  // IF setting strict = 1, check that MTF macro is enabled
}

uint8_t pfwl_set_max_trials(pfwl_state_t *state, uint16_t max_trials) {
<<<<<<< HEAD
  if(state){
    state->max_trials = max_trials;
    return 0;
  }else{
=======
  if (state) {
    state->max_trials = max_trials;
    return 0;
  } else {
>>>>>>> SoftAtHome/master
    return 1;
  }
}

<<<<<<< HEAD
uint8_t pfwl_defragmentation_enable_ipv4(pfwl_state_t *state,
                                         uint16_t table_size) {
  if (state) {
    state->ipv4_frag_state =
        pfwl_reordering_enable_ipv4_fragmentation(table_size);
=======
uint8_t pfwl_defragmentation_enable_ipv4(pfwl_state_t *state, uint16_t table_size) {
  if (state) {
    state->ipv4_frag_state = pfwl_reordering_enable_ipv4_fragmentation(table_size);
>>>>>>> SoftAtHome/master
    assert(state->ipv4_frag_state);
    return 0;
  } else {
    return 1;
  }
}

<<<<<<< HEAD
uint8_t pfwl_defragmentation_enable_ipv6(pfwl_state_t *state,
                                         uint16_t table_size) {
  if (likely(state)) {
    state->ipv6_frag_state =
        pfwl_reordering_enable_ipv6_fragmentation(table_size);
=======
uint8_t pfwl_defragmentation_enable_ipv6(pfwl_state_t *state, uint16_t table_size) {
  if (likely(state)) {
    state->ipv6_frag_state = pfwl_reordering_enable_ipv6_fragmentation(table_size);
>>>>>>> SoftAtHome/master
    assert(state->ipv6_frag_state);
    return 0;
  } else {
    return 1;
  }
}

<<<<<<< HEAD
uint8_t pfwl_defragmentation_set_per_host_memory_limit_ipv4(
    pfwl_state_t *state, uint32_t per_host_memory_limit) {
  if (likely(state)) {
    assert(state->ipv4_frag_state);
    pfwl_reordering_ipv4_fragmentation_set_per_host_memory_limit(
        state->ipv4_frag_state, per_host_memory_limit);
=======
uint8_t pfwl_defragmentation_set_per_host_memory_limit_ipv4(pfwl_state_t *state, uint32_t per_host_memory_limit) {
  if (likely(state)) {
    assert(state->ipv4_frag_state);
    pfwl_reordering_ipv4_fragmentation_set_per_host_memory_limit(state->ipv4_frag_state, per_host_memory_limit);
>>>>>>> SoftAtHome/master
    return 0;
  } else {
    return 1;
  }
}

<<<<<<< HEAD
uint8_t pfwl_defragmentation_set_per_host_memory_limit_ipv6(
    pfwl_state_t *state, uint32_t per_host_memory_limit) {
  if (likely(state)) {
    assert(state->ipv6_frag_state);
    pfwl_reordering_ipv6_fragmentation_set_per_host_memory_limit(
        state->ipv6_frag_state, per_host_memory_limit);
=======
uint8_t pfwl_defragmentation_set_per_host_memory_limit_ipv6(pfwl_state_t *state, uint32_t per_host_memory_limit) {
  if (likely(state)) {
    assert(state->ipv6_frag_state);
    pfwl_reordering_ipv6_fragmentation_set_per_host_memory_limit(state->ipv6_frag_state, per_host_memory_limit);
>>>>>>> SoftAtHome/master
    return 0;
  } else {
    return 1;
  }
}

<<<<<<< HEAD
uint8_t
pfwl_defragmentation_set_total_memory_limit_ipv4(pfwl_state_t *state,
                                                 uint32_t total_memory_limit) {
  if (likely(state)) {
    assert(state->ipv4_frag_state);
    pfwl_reordering_ipv4_fragmentation_set_total_memory_limit(
        state->ipv4_frag_state, total_memory_limit);
=======
uint8_t pfwl_defragmentation_set_total_memory_limit_ipv4(pfwl_state_t *state, uint32_t total_memory_limit) {
  if (likely(state)) {
    assert(state->ipv4_frag_state);
    pfwl_reordering_ipv4_fragmentation_set_total_memory_limit(state->ipv4_frag_state, total_memory_limit);
>>>>>>> SoftAtHome/master
    return 0;
  } else {
    return 1;
  }
}

<<<<<<< HEAD
uint8_t
pfwl_defragmentation_set_total_memory_limit_ipv6(pfwl_state_t *state,
                                                 uint32_t total_memory_limit) {
  if (likely(state)) {
    assert(state->ipv6_frag_state);
    pfwl_reordering_ipv6_fragmentation_set_total_memory_limit(
        state->ipv6_frag_state, total_memory_limit);
=======
uint8_t pfwl_defragmentation_set_total_memory_limit_ipv6(pfwl_state_t *state, uint32_t total_memory_limit) {
  if (likely(state)) {
    assert(state->ipv6_frag_state);
    pfwl_reordering_ipv6_fragmentation_set_total_memory_limit(state->ipv6_frag_state, total_memory_limit);
>>>>>>> SoftAtHome/master
    return 0;
  } else {
    return 1;
  }
}

<<<<<<< HEAD
uint8_t
pfwl_defragmentation_set_reassembly_timeout_ipv4(pfwl_state_t *state,
                                                 uint8_t timeout_seconds) {
  if (likely(state)) {
    assert(state->ipv4_frag_state);
    pfwl_reordering_ipv4_fragmentation_set_reassembly_timeout(
        state->ipv4_frag_state, timeout_seconds);
=======
uint8_t pfwl_defragmentation_set_reassembly_timeout_ipv4(pfwl_state_t *state, uint8_t timeout_seconds) {
  if (likely(state)) {
    assert(state->ipv4_frag_state);
    pfwl_reordering_ipv4_fragmentation_set_reassembly_timeout(state->ipv4_frag_state, timeout_seconds);
>>>>>>> SoftAtHome/master
    return 0;
  } else {
    return 1;
  }
}

<<<<<<< HEAD
uint8_t
pfwl_defragmentation_set_reassembly_timeout_ipv6(pfwl_state_t *state,
                                                 uint8_t timeout_seconds) {
  if (likely(state)) {
    assert(state->ipv6_frag_state);
    pfwl_reordering_ipv6_fragmentation_set_reassembly_timeout(
        state->ipv6_frag_state, timeout_seconds);
=======
uint8_t pfwl_defragmentation_set_reassembly_timeout_ipv6(pfwl_state_t *state, uint8_t timeout_seconds) {
  if (likely(state)) {
    assert(state->ipv6_frag_state);
    pfwl_reordering_ipv6_fragmentation_set_reassembly_timeout(state->ipv6_frag_state, timeout_seconds);
>>>>>>> SoftAtHome/master
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_defragmentation_disable_ipv4(pfwl_state_t *state) {
  if (likely(state)) {
    pfwl_reordering_disable_ipv4_fragmentation(state->ipv4_frag_state);
    state->ipv4_frag_state = NULL;
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_defragmentation_disable_ipv6(pfwl_state_t *state) {
  if (likely(state)) {
    pfwl_reordering_disable_ipv6_fragmentation(state->ipv6_frag_state);
    state->ipv6_frag_state = NULL;
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_tcp_reordering_enable(pfwl_state_t *state) {
  if (likely(state)) {
    state->tcp_reordering_enabled = 1;
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_tcp_reordering_disable(pfwl_state_t *state) {
  if (likely(state)) {
    state->tcp_reordering_enabled = 0;
    return 0;
  } else {
    return 1;
  }
}

void pfwl_terminate(pfwl_state_t *state) {
  if (likely(state)) {
    pfwl_defragmentation_disable_ipv4(state);
    pfwl_defragmentation_disable_ipv6(state);
    pfwl_tcp_reordering_disable(state);

    pfwl_flow_table_delete(state->flow_table, state->ts_unit);
<<<<<<< HEAD
=======

    pfwl_field_tags_delete(state);

>>>>>>> SoftAtHome/master
    free(state);
  }
}

<<<<<<< HEAD
pfwl_status_t pfwl_dissect_from_L2(pfwl_state_t *state,
                                   const unsigned char *pkt, size_t length,
                                   double timestamp,
                                   pfwl_protocol_l2_t datalink_type,
                                   pfwl_dissection_info_t *dissection_info) {
  memset(dissection_info, 0, sizeof(pfwl_dissection_info_t));
  pfwl_status_t status;
  status = pfwl_dissect_L2(pkt, datalink_type, dissection_info);
  if (unlikely(status < PFWL_STATUS_OK)) {
    return status;
  }
  return pfwl_dissect_from_L3(state, pkt + dissection_info->l2.length,
                              length - dissection_info->l2.length, timestamp,
                              dissection_info);
}

pfwl_flow_t *pfwl_parse_L4_internal(pfwl_state_t *state,
                                    const unsigned char *pkt, size_t length,
                                    uint32_t current_time,
                                    pfwl_dissection_info_t *dissection_info);

pfwl_status_t pfwl_dissect_from_L3(pfwl_state_t *state,
                                   const unsigned char *pkt, size_t length,
                                   double timestamp,
=======
pfwl_status_t pfwl_dissect_from_L2(pfwl_state_t *state, const unsigned char *pkt, size_t length, double timestamp,
                                   pfwl_protocol_l2_t datalink_type, pfwl_dissection_info_t *dissection_info) {
  memset(dissection_info, 0, sizeof(pfwl_dissection_info_t));
  pfwl_status_t status;
  status = pfwl_dissect_L2_sized(pkt, length, datalink_type, dissection_info);
  if (unlikely(status < PFWL_STATUS_OK)) {
    return status;
  }
  return pfwl_dissect_from_L3(state, pkt + dissection_info->l2.length, length - dissection_info->l2.length, timestamp,
                              dissection_info);
}

pfwl_flow_t *pfwl_parse_L4_internal(pfwl_state_t *state, const unsigned char *pkt, size_t length, uint32_t current_time,
                                    pfwl_dissection_info_t *dissection_info);

pfwl_status_t pfwl_dissect_from_L3(pfwl_state_t *state, const unsigned char *pkt, size_t length, double timestamp,
>>>>>>> SoftAtHome/master
                                   pfwl_dissection_info_t *r) {
  pfwl_status_t status;
  status = pfwl_dissect_L3(state, pkt, length, timestamp, r);

  if (unlikely(status == PFWL_STATUS_IP_FRAGMENT || status < 0)) {
    return status;
  }

  const unsigned char *l4_pkt;
  size_t l4_pkt_len;
  if (r->l3.refrag_pkt) {
    l4_pkt = r->l3.refrag_pkt + r->l3.length;
    l4_pkt_len = r->l3.refrag_pkt_len - r->l3.length;
  } else {
    l4_pkt = pkt + r->l3.length;
    l4_pkt_len = r->l3.payload_length;
  }
  return pfwl_dissect_from_L4(state, l4_pkt, l4_pkt_len, timestamp, r);
}

<<<<<<< HEAD
uint8_t pfwl_set_protocol_accuracy_L7(pfwl_state_t *state,
                                      pfwl_protocol_l7_t protocol,
=======
uint8_t pfwl_set_protocol_accuracy_L7(pfwl_state_t *state, pfwl_protocol_l7_t protocol,
>>>>>>> SoftAtHome/master
                                      pfwl_dissector_accuracy_t accuracy) {
  if (state) {
    state->inspectors_accuracy[protocol] = accuracy;
    return 0;
  } else {
    return 1;
  }
}

const char *pfwl_get_status_msg(pfwl_status_t status_code) {
  switch (status_code) {
  case PFWL_ERROR_L2_PARSING:
    return "ERROR: The L2 data is unsupported, truncated or corrupted.";
  case PFWL_ERROR_L3_PARSING:
    return "ERROR: The L3 data is unsupported, truncated or corrupted.";
  case PFWL_ERROR_L4_PARSING:
    return "ERROR: The L4 data is unsupported, truncated or corrupted.";
  case PFWL_ERROR_WRONG_IPVERSION:
    return "ERROR: The packet is neither IPv4 nor IPv6.";
  case PFWL_ERROR_IPSEC_NOTSUPPORTED:
    return "ERROR: The packet is encrypted using IPSEC. "
           "IPSEC is not supported.";
  case PFWL_ERROR_IPV6_HDR_PARSING:
    return "ERROR: IPv6 headers parsing.";
  case PFWL_ERROR_MAX_FLOWS:
    return "ERROR: The maximum number of active flows has been"
           " reached. Please increase it when initializing the libray";
  case PFWL_STATUS_OK:
    return "STATUS: Everything is ok.";
  case PFWL_STATUS_IP_FRAGMENT:
    return "STATUS: The received IP datagram is a fragment of a "
           " bigger datagram.";
  case PFWL_STATUS_IP_DATA_REBUILT:
    return "STATUS: The received IP datagram is the last fragment"
           " of a bigger datagram. The original datagram has been"
           " recomposed and the memory needs to be freed when"
           " the data is not needed anymore.";
  case PFWL_STATUS_TCP_OUT_OF_ORDER:
    return "STATUS: The received TCP segment is out of order in "
           " its stream. It will be buffered waiting for in order"
           " segments.";
  case PFWL_STATUS_TCP_CONNECTION_TERMINATED:
    return "STATUS: The TCP connection is terminated.";
  default:
    return "STATUS: Not existing status code.";
  }
}

<<<<<<< HEAD
uint8_t pfwl_set_flow_cleaner_callback(pfwl_state_t *state,
                                       pfwl_flow_cleaner_callback_t *cleaner) {
  if(state){
    pflw_flow_table_set_flow_cleaner_callback(state->flow_table, cleaner);
    return 0;
  }else{
=======
uint8_t pfwl_set_flow_cleaner_callback(pfwl_state_t *state, pfwl_flow_cleaner_callback_t *cleaner) {
  if (state) {
    pflw_flow_table_set_flow_cleaner_callback(state->flow_table, cleaner);
    return 0;
  } else {
>>>>>>> SoftAtHome/master
    return 1;
  }
}

pfwl_protocol_l7_t pfwl_get_L7_field_protocol(pfwl_field_id_t field);

<<<<<<< HEAD
uint8_t pfwl_set_flow_termination_callback(pfwl_state_t *state,
                                           pfwl_flow_termination_callback_t *cleaner){
  if(state){
    pflw_flow_table_set_flow_termination_callback(state->flow_table, cleaner);
    return 0;
  }else{
=======
uint8_t pfwl_set_flow_termination_callback(pfwl_state_t *state, pfwl_flow_termination_callback_t *cleaner) {
  if (state) {
    pflw_flow_table_set_flow_termination_callback(state->flow_table, cleaner);
    return 0;
  } else {
>>>>>>> SoftAtHome/master
    return 1;
  }
}

<<<<<<< HEAD
uint8_t pfwl_statistic_add(pfwl_state_t* state, pfwl_statistic_t stat){
=======
uint8_t pfwl_statistic_add(pfwl_state_t *state, pfwl_statistic_t stat) {
>>>>>>> SoftAtHome/master
  state->stats_to_compute[stat] = 1;
  return 0;
}

<<<<<<< HEAD
uint8_t pfwl_statistic_remove(pfwl_state_t* state, pfwl_statistic_t stat){
=======
uint8_t pfwl_statistic_remove(pfwl_state_t *state, pfwl_statistic_t stat) {
>>>>>>> SoftAtHome/master
  state->stats_to_compute[stat] = 0;
  return 0;
}

<<<<<<< HEAD
uint8_t pfwl_field_add_L7_internal(pfwl_state_t *state, pfwl_field_id_t field,
                                   uint8_t* fields_to_extract, uint8_t* fields_to_extract_num) {
=======
uint8_t pfwl_field_add_L7_internal(pfwl_state_t *state, pfwl_field_id_t field, uint8_t *fields_to_extract,
                                   uint8_t *fields_to_extract_num) {
>>>>>>> SoftAtHome/master
  if (state) {
    if (!fields_to_extract[field]) {
      pfwl_protocol_l7_t protocol = pfwl_get_L7_field_protocol(field);
      if (protocol == PFWL_PROTO_L7_NUM) {
        return 0;
      }
      ++fields_to_extract_num[protocol];
      pfwl_protocol_l7_enable(state, protocol);
<<<<<<< HEAD
      pfwl_set_protocol_accuracy_L7(
          state, protocol,
          PFWL_DISSECTOR_ACCURACY_HIGH); // TODO: mmm, the problem is that we
                                         // do not set back the original
                                         // accuracy when doing field_remove
=======
      pfwl_set_protocol_accuracy_L7(state, protocol,
                                    PFWL_DISSECTOR_ACCURACY_HIGH); // TODO: mmm, the problem is that we
                                                                   // do not set back the original
                                                                   // accuracy when doing field_remove
>>>>>>> SoftAtHome/master
    }
    fields_to_extract[field] = 1;
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_field_add_L7(pfwl_state_t *state, pfwl_field_id_t field) {
<<<<<<< HEAD
=======
  if (!state)
    return 1;
>>>>>>> SoftAtHome/master
  return pfwl_field_add_L7_internal(state, field, state->fields_to_extract, state->fields_to_extract_num);
}

uint8_t pfwl_field_remove_L7(pfwl_state_t *state, pfwl_field_id_t field) {
  if (state) {
    if (state->fields_to_extract[field]) {
      pfwl_protocol_l7_t protocol = pfwl_get_L7_field_protocol(field);
      if (protocol == PFWL_PROTO_L7_NUM) {
        return 0;
      }
      --state->fields_to_extract_num[protocol];
    }
    state->fields_to_extract[field] = 0;
    return 0;
  } else {
    return 1;
  }
}

<<<<<<< HEAD
uint8_t pfwl_protocol_field_required(pfwl_state_t *state,
                                     pfwl_flow_info_private_t* flow_info_private,
                                     pfwl_field_id_t field) {
  if (state) {
    if(flow_info_private->info_public->protocols_l7_num &&
       flow_info_private->info_public->protocols_l7[flow_info_private->info_public->protocols_l7_num - 1] == PFWL_PROTO_L7_UNKNOWN){
      return state->fields_to_extract[field];
    }else{
=======
uint8_t pfwl_protocol_field_required(pfwl_state_t *state, pfwl_flow_info_private_t *flow_info_private,
                                     pfwl_field_id_t field) {
  if (state) {
    if (flow_info_private->info_public->protocols_l7_num &&
        flow_info_private->info_public->protocols_l7[flow_info_private->info_public->protocols_l7_num - 1] ==
            PFWL_PROTO_L7_UNKNOWN) {
      return state->fields_to_extract[field];
    } else {
>>>>>>> SoftAtHome/master
      return state->fields_to_extract[field] || state->fields_support[field];
    }
  } else {
    return 0;
  }
}

<<<<<<< HEAD
pfwl_flow_info_private_t* pfwl_create_flow_info_private(pfwl_state_t* state,
                                                        const pfwl_dissection_info_t *dissection_info){
  pfwl_flow_t* flow = malloc(sizeof(pfwl_flow_t));
  pfwl_init_flow(flow, dissection_info, state->protocols_to_inspect,
                 state->tcp_reordering_enabled, state->next_flow_id++,
                 0, 0);
  return &(flow->info_private);
}

void pfwl_destroy_flow_info_private(pfwl_flow_info_private_t* info){
  free(info->flow);
}


void pfwl_init_flow_info(pfwl_state_t *state,
                         pfwl_flow_info_private_t *flow_info_private) {
  pfwl_init_flow_info_internal(flow_info_private, state->protocols_to_inspect,
                               state->tcp_reordering_enabled);
}

void pfwl_field_string_set(pfwl_field_t *fields, pfwl_field_id_t id,
                           const unsigned char *s, size_t len) {
=======
pfwl_flow_info_private_t *pfwl_create_flow_info_private(pfwl_state_t *state,
                                                        const pfwl_dissection_info_t *dissection_info) {
  pfwl_flow_t *flow = malloc(sizeof(pfwl_flow_t));
  pfwl_init_flow(flow, dissection_info, state->protocols_to_inspect, state->tcp_reordering_enabled,
                 state->next_flow_id++, 0, 0);
  return &(flow->info_private);
}

void pfwl_destroy_flow_info_private(pfwl_flow_info_private_t *info) {
  free(info->flow);
}

void pfwl_init_flow_info(pfwl_state_t *state, pfwl_flow_info_private_t *flow_info_private) {
  pfwl_init_flow_info_internal(flow_info_private, state->protocols_to_inspect, state->tcp_reordering_enabled);
}

void pfwl_field_string_set(pfwl_field_t *fields, pfwl_field_id_t id, const unsigned char *s, size_t len) {
>>>>>>> SoftAtHome/master
  fields[id].present = 1;
  fields[id].basic.string.value = s;
  fields[id].basic.string.length = len;
}

// ATTENTION: num must be in host byte order
<<<<<<< HEAD
void pfwl_field_number_set(pfwl_field_t *fields, pfwl_field_id_t id,
                           int64_t num) {
=======
void pfwl_field_number_set(pfwl_field_t *fields, pfwl_field_id_t id, int64_t num) {
>>>>>>> SoftAtHome/master
  fields[id].present = 1;
  fields[id].basic.number = num;
}

<<<<<<< HEAD
void pfwl_array_push_back_string(pfwl_array_t *array, const unsigned char *s,
                                 size_t len) {
=======
void pfwl_array_push_back_string(pfwl_array_t *array, const unsigned char *s, size_t len) {
>>>>>>> SoftAtHome/master
  ((pfwl_string_t *) array->values)[array->length].value = s;
  ((pfwl_string_t *) array->values)[array->length].length = len;
  ++array->length;
}

<<<<<<< HEAD
void pfwl_field_array_push_back_string(pfwl_field_t *fields, pfwl_field_id_t id,
                                       const unsigned char *s, size_t len) {
=======
void pfwl_field_array_push_back_string(pfwl_field_t *fields, pfwl_field_id_t id, const unsigned char *s, size_t len) {
>>>>>>> SoftAtHome/master
  fields[id].present = 1;
  pfwl_array_push_back_string(&(fields[id].array), s, len);
}

<<<<<<< HEAD
uint8_t pfwl_field_string_get(pfwl_field_t *fields, pfwl_field_id_t id,
                              pfwl_string_t *string) {
=======
uint8_t pfwl_field_string_get(pfwl_field_t *fields, pfwl_field_id_t id, pfwl_string_t *string) {
>>>>>>> SoftAtHome/master
  if (fields[id].present) {
    *string = fields[id].basic.string;
    return 0;
  } else {
    return 1;
  }
}

<<<<<<< HEAD
uint8_t pfwl_field_number_get(pfwl_field_t *fields, pfwl_field_id_t id,
                              int64_t *num) {
=======
uint8_t pfwl_field_number_get(pfwl_field_t *fields, pfwl_field_id_t id, int64_t *num) {
>>>>>>> SoftAtHome/master
  if (fields[id].present) {
    *num = fields[id].basic.number;
    return 0;
  } else {
    return 1;
  }
}

<<<<<<< HEAD
uint8_t pfwl_field_array_length(pfwl_field_t *fields, pfwl_field_id_t id,
                                size_t *length) {
=======
uint8_t pfwl_field_array_length(pfwl_field_t *fields, pfwl_field_id_t id, size_t *length) {
>>>>>>> SoftAtHome/master
  if (fields[id].present) {
    *length = fields[id].array.length;
    return 0;
  } else {
    return 1;
  }
}

<<<<<<< HEAD
uint8_t pfwl_field_array_get_pair(pfwl_field_t *fields, pfwl_field_id_t id,
                                  size_t position, pfwl_pair_t *pair) {
=======
uint8_t pfwl_field_array_get_pair(pfwl_field_t *fields, pfwl_field_id_t id, size_t position, pfwl_pair_t *pair) {
>>>>>>> SoftAtHome/master
  if (fields[id].present) {
    *pair = ((pfwl_pair_t *) fields[id].array.values)[position];
    return 0;
  } else {
    return 1;
  }
}

<<<<<<< HEAD
uint8_t pfwl_http_get_header_internal(pfwl_field_t field,
                             const char *header_name,
                             pfwl_string_t *header_value) {
=======
uint8_t pfwl_http_get_header_internal(pfwl_field_t field, const char *header_name, pfwl_string_t *header_value) {
>>>>>>> SoftAtHome/master
  if (field.present) {
    for (size_t i = 0; i < field.mmap.length; i++) {
      pfwl_pair_t pair = ((pfwl_pair_t *) field.mmap.values)[i];
      pfwl_string_t key = pair.first.string;
      if (key.length && !strncasecmp(header_name, (const char *) key.value, key.length)) {
        *header_value = pair.second.string;
        return 0;
      }
    }
  }
  return 1;
}

<<<<<<< HEAD
uint8_t pfwl_http_get_header(pfwl_dissection_info_t *dissection_info,
                             const char *header_name,
                             pfwl_string_t *header_value) {
  return pfwl_http_get_header_internal(dissection_info->l7.protocol_fields[PFWL_FIELDS_L7_HTTP_HEADERS],
                                       header_name,
                                       header_value);
}

uint8_t pfwl_has_protocol_L7(pfwl_dissection_info_t* dissection_info, pfwl_protocol_l7_t protocol){
  for(size_t i = 0; i < dissection_info->l7.protocols_num; i++){
    if(dissection_info->l7.protocols[i] == protocol){
=======
uint8_t pfwl_http_get_header(pfwl_dissection_info_t *dissection_info, const char *header_name,
                             pfwl_string_t *header_value) {
  return pfwl_http_get_header_internal(dissection_info->l7.protocol_fields[PFWL_FIELDS_L7_HTTP_HEADERS], header_name,
                                       header_value);
}

uint8_t pfwl_has_protocol_L7(pfwl_dissection_info_t *dissection_info, pfwl_protocol_l7_t protocol) {
  for (size_t i = 0; i < dissection_info->l7.protocols_num; i++) {
    if (dissection_info->l7.protocols[i] == protocol) {
>>>>>>> SoftAtHome/master
      return 1;
    }
  }
  return 0;
}
