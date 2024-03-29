/*
 * ipv6_reassembly.c
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
#include <peafowl/ipv6_reassembly.h>
#include <peafowl/reassembly.h>
#include <peafowl/utils.h>

#include <inttypes.h>
#include <netinet/ip6.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>

#if PFWL_THREAD_SAFETY_ENABLED == 1
#include <ff/spin-lock.hpp>
#endif

#define PFWL_DEBUG_FRAGMENTATION_v6 0

#define debug_print(fmt, ...)            \
  do {                                   \
    if (PFWL_DEBUG_FRAGMENTATION_v6)     \
      fprintf(stderr, fmt, __VA_ARGS__); \
  } while (0)

#define PFWL_IP_FRAGMENTATION_MAX_DATAGRAM_SIZE 65535
#define PFWL_IPv6_FRAGMENTATION_MINIMUM_MTU 1280

typedef struct pfwl_ipv6_fragmentation_flow pfwl_ipv6_fragmentation_flow_t;
typedef struct pfwl_ipv6_fragmentation_source pfwl_ipv6_fragmentation_source_t;

typedef struct pfwl_ipv6_fragmentation_flow {
  /* Pointer to the unfragmentable part. */
  unsigned char *unfragmentable;
  uint16_t unfragmentable_length;
  /*Total length of the final datagram (without unfragmentable part).*/
  uint16_t len;
  /*
   * NOTE: Differently from ipv6, in IPv6 the key is <id, src, dest>
   * (so no next header value).
   */
  uint32_t id;
  struct in6_addr dstaddr;
  /* Linked list of received fragments. */
  pfwl_reassembly_fragment_t *fragments;
  /*
   * For a given source, pointer to the previous and next flows
   * started from that source
   */
  pfwl_ipv6_fragmentation_flow_t *next;
  pfwl_ipv6_fragmentation_flow_t *prev;
  pfwl_reassembly_timer_t timer;
  pfwl_ipv6_fragmentation_source_t *source;
} pfwl_ipv6_fragmentation_flow_t;

typedef struct pfwl_ipv6_fragmentation_source {
  pfwl_ipv6_fragmentation_flow_t *flows;
  uint32_t source_used_mem;
  struct in6_addr ipv6_srcaddr;
  uint16_t row;
  pfwl_ipv6_fragmentation_source_t *prev;
  pfwl_ipv6_fragmentation_source_t *next;
} pfwl_ipv6_fragmentation_source_t;

typedef struct pfwl_ipv6_fragmentation_state {
  /**
   *  Is an hash table containing associations between source IP
   *  address and fragments generated by that address.
   **/
  pfwl_ipv6_fragmentation_source_t **table;
  uint32_t total_used_mem;
  uint16_t table_size;

  /** List of timers. **/
  pfwl_reassembly_timer_t *timer_head, *timer_tail;

  /** Memory limits. **/
  uint32_t per_source_memory_limit;
  uint32_t total_memory_limit;

  /** Reassembly timeout. **/
  uint8_t timeout;
#if PFWL_THREAD_SAFETY_ENABLED == 1
  ff::lock_t lock;
#endif
} pfwl_ipv6_fragmentation_state_t;

#ifndef PFWL_DEBUG
static
#if PFWL_USE_INLINING == 1
    inline
#endif
#endif
    void
    pfwl_ipv6_fragmentation_delete_source(pfwl_ipv6_fragmentation_state_t *state,
                                          pfwl_ipv6_fragmentation_source_t *source);

/**
 * Enables the IPv6 defragmentation.
 * @param table_size  The size of the table used to store the fragments.
 * @return            A pointer to the IPv6 defragmentation handle.
 */
pfwl_ipv6_fragmentation_state_t *pfwl_reordering_enable_ipv6_fragmentation(uint16_t table_size) {
  pfwl_ipv6_fragmentation_state_t *r =
      (pfwl_ipv6_fragmentation_state_t *) calloc(1, sizeof(pfwl_ipv6_fragmentation_state_t));
  if (r == NULL) {
    return NULL;
  }
  r->table_size = table_size;
  r->table = (pfwl_ipv6_fragmentation_source_t **) malloc(table_size * sizeof(pfwl_ipv6_fragmentation_source_t *));
  if (r->table == NULL) {
    free(r);
    return NULL;
  }
  uint16_t i;
  for (i = 0; i < table_size; i++) {
    r->table[i] = NULL;
  }
  r->timer_head = NULL;
  r->timer_tail = NULL;
  r->per_source_memory_limit = PFWL_IPv6_FRAGMENTATION_DEFAULT_PER_HOST_MEMORY_LIMIT;
  r->total_memory_limit = PFWL_IPv6_FRAGMENTATION_DEFAULT_TOTAL_MEMORY_LIMIT;
  r->timeout = PFWL_IPv6_FRAGMENTATION_DEFAULT_REASSEMBLY_TIMEOUT;
  r->total_used_mem = 0;
#if PFWL_THREAD_SAFETY_ENABLED == 1
  ff::init_unlocked(r->lock);
#endif
  return r;
}

void pfwl_reordering_ipv6_fragmentation_set_per_host_memory_limit(pfwl_ipv6_fragmentation_state_t *frag_state,
                                                                  uint32_t per_host_memory_limit) {
  frag_state->per_source_memory_limit = per_host_memory_limit;
}

void pfwl_reordering_ipv6_fragmentation_set_total_memory_limit(pfwl_ipv6_fragmentation_state_t *frag_state,
                                                               uint32_t total_memory_limit) {
  frag_state->total_memory_limit = total_memory_limit;
}

void pfwl_reordering_ipv6_fragmentation_set_reassembly_timeout(pfwl_ipv6_fragmentation_state_t *frag_state,
                                                               uint8_t timeout_seconds) {
  frag_state->timeout = timeout_seconds;
}

void pfwl_reordering_disable_ipv6_fragmentation(pfwl_ipv6_fragmentation_state_t *frag_state) {
  if (frag_state == NULL)
    return;
  pfwl_ipv6_fragmentation_source_t *source, *tmp_source;
  if (frag_state->table) {
    uint16_t i;
    for (i = 0; i < frag_state->table_size; i++) {
      if (frag_state->table[i]) {
        source = frag_state->table[i];
        while (source) {
          tmp_source = source->next;
          pfwl_ipv6_fragmentation_delete_source(frag_state, source);
          source = tmp_source;
        }
      }
    }
    free(frag_state->table);
  }
  free(frag_state);
}

#ifndef PFWL_DEBUG
static
#if PFWL_USE_INLINING == 1
    inline
#endif
#endif
    /**  Shift-Add-XOR hash. **/
    uint16_t
    pfwl_ipv6_fragmentation_hash_function(pfwl_ipv6_fragmentation_state_t *state, struct in6_addr addr) {
  uint16_t h = 0;
  uint8_t i;

  for (i = 0; i < 16; i++)
    h ^= (h << 5) + (h >> 2) + addr.s6_addr[i];

  return h % state->table_size;
}

#ifndef PFWL_DEBUG
static
#endif
    /**
     * Try to find the specific source. If it is not find, then creates it.
     * \param state The state of the defragmentation module.
     * \param addr The source address.
     * \returns A pointer to the source.
     */
    pfwl_ipv6_fragmentation_source_t *
    pfwl_ipv6_fragmentation_find_or_create_source(pfwl_ipv6_fragmentation_state_t *state, struct in6_addr addr) {
  uint16_t hash_index = pfwl_ipv6_fragmentation_hash_function(state, addr);
  pfwl_ipv6_fragmentation_source_t *source, *head;

  head = state->table[hash_index];

  for (source = head; source != NULL; source = source->next) {
    if (pfwl_v6_addresses_equal(source->ipv6_srcaddr, addr)) {
      return source;
    }
  }

  /** Not found, so create it. **/
  source = (pfwl_ipv6_fragmentation_source_t *) malloc(sizeof(pfwl_ipv6_fragmentation_source_t));
  if (unlikely(source == NULL)) {
    return NULL;
  }
  source->row = hash_index;
  source->flows = NULL;

  source->ipv6_srcaddr = addr;
  source->source_used_mem = sizeof(pfwl_ipv6_fragmentation_source_t);
  state->total_used_mem += sizeof(pfwl_ipv6_fragmentation_source_t);

  /** Insertion at the beginning of the list. **/
  source->prev = NULL;
  source->next = head;
  if (head)
    head->prev = source;
  state->table[hash_index] = source;

  return source;
}

#ifndef PFWL_DEBUG
static
#endif
    void
    pfwl_ipv6_fragmentation_delete_flow(pfwl_ipv6_fragmentation_state_t *state, pfwl_ipv6_fragmentation_flow_t *flow) {
  pfwl_reassembly_fragment_t *frag, *temp_frag;

  pfwl_ipv6_fragmentation_source_t *source = flow->source;

  source->source_used_mem -= sizeof(pfwl_ipv6_fragmentation_flow_t);
  state->total_used_mem -= sizeof(pfwl_ipv6_fragmentation_flow_t);

  /* Stop the timer and delete it. */
  pfwl_reassembly_delete_timer(&(state->timer_head), &(state->timer_tail), &(flow->timer));

  /* Release all fragment data. */
  frag = flow->fragments;
  while (frag) {
    temp_frag = frag->next;
    source->source_used_mem -= (frag->end - frag->offset);
    state->total_used_mem -= (frag->end - frag->offset);

    free(frag->ptr);
    free(frag);
    frag = temp_frag;
  }

  /** Delete the IP header. **/
  if (flow->unfragmentable) {
    source->source_used_mem -= flow->unfragmentable_length;
    state->total_used_mem -= flow->unfragmentable_length;
    free(flow->unfragmentable);
  }

  /*
   * Remove the flow from the list of the flows. If no more flows for
   * this source, then delete the source.
   */
  if (flow->prev == NULL) {
    source->flows = flow->next;
    if (source->flows != NULL)
      source->flows->prev = NULL;
  } else {
    flow->prev->next = flow->next;
    if (flow->next)
      flow->next->prev = flow->prev;
  }
  free(flow);
}

#ifndef PFWL_DEBUG
static
#endif
    pfwl_ipv6_fragmentation_flow_t *
    pfwl_ipv6_fragmentation_find_or_create_flow(pfwl_ipv6_fragmentation_state_t *state,
                                                pfwl_ipv6_fragmentation_source_t *source, uint32_t id,
                                                struct in6_addr dstaddr, uint32_t current_time) {
  pfwl_ipv6_fragmentation_flow_t *flow;
  for (flow = source->flows; flow != NULL; flow = flow->next) {
    /**
     * The source is matched for sure because all the flows
     * will have the same source.
     **/
    if (id == flow->id && pfwl_v6_addresses_equal(dstaddr, flow->dstaddr)) {
      return flow;
    }
  }

  /** Not found, create a new flow. **/
  flow = (pfwl_ipv6_fragmentation_flow_t *) malloc(sizeof(pfwl_ipv6_fragmentation_flow_t));
  if (unlikely(flow == NULL)) {
    return NULL;
  }

  source->source_used_mem += sizeof(pfwl_ipv6_fragmentation_flow_t);
  state->total_used_mem += sizeof(pfwl_ipv6_fragmentation_flow_t);

  flow->fragments = NULL;
  flow->source = source;
  flow->len = 0;
  /* Add this entry to the queue of flows. */
  flow->prev = NULL;
  flow->next = source->flows;
  if (flow->next)
    flow->next->prev = flow;
  source->flows = flow;
  /* Set the timer. */
  flow->timer.expiration_time = current_time + state->timeout;
  flow->timer.data = flow;
  pfwl_reassembly_add_timer(&(state->timer_head), &(state->timer_tail), &(flow->timer));
  /* Fragments will be added later. */
  flow->fragments = NULL;
  flow->unfragmentable = NULL;
  flow->id = id;
  flow->dstaddr = dstaddr;
  return flow;
}

#ifndef PFWL_DEBUG
static
#endif
    unsigned char *
    pfwl_ipv6_fragmentation_build_complete_datagram(pfwl_ipv6_fragmentation_state_t *state,
                                                    pfwl_ipv6_fragmentation_flow_t *flow) {
  unsigned char *pkt_beginning, *pkt_data;
  struct ip6_hdr *iph;
  uint16_t len;
  int32_t count;

  /* Allocate a new buffer for the datagram. */
  len = flow->len;

  pfwl_ipv6_fragmentation_source_t *source = flow->source;

  uint32_t tot_len = flow->unfragmentable_length + len;

  if (unlikely(tot_len > PFWL_IP_FRAGMENTATION_MAX_DATAGRAM_SIZE)) {
    pfwl_ipv6_fragmentation_delete_flow(state, flow);
    if (source->flows == NULL)
      pfwl_ipv6_fragmentation_delete_source(state, source);
    return NULL;
  }

  if (unlikely((pkt_beginning = (unsigned char *) malloc(flow->unfragmentable_length + len)) == NULL)) {
    pfwl_ipv6_fragmentation_delete_flow(state, flow);
    if (source->flows == NULL)
      pfwl_ipv6_fragmentation_delete_source(state, source);
    return NULL;
  }

  memcpy(pkt_beginning, (flow->unfragmentable), flow->unfragmentable_length);
  pkt_data = pkt_beginning + flow->unfragmentable_length;

  count = pfwl_reassembly_ip_compact_fragments(flow->fragments, &pkt_data, len);

  /**
   * Misbehaving packet, real size is different from that obtained
   * from the last fragment.
   **/
  if (count == -1) {
    free(pkt_beginning);
    return NULL;
  }

  /** Put the correct informations in the IP header. **/
  iph = (struct ip6_hdr *) pkt_beginning;
  iph->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(count + flow->unfragmentable_length - sizeof(struct ip6_hdr));

  /** We recompacted the flow (datagram), so now we can delete it. **/
  pfwl_ipv6_fragmentation_delete_flow(state, flow);
  if (source->flows == NULL)
    pfwl_ipv6_fragmentation_delete_source(state, source);

  return pkt_beginning;
}

#ifndef PFWL_DEBUG
static
#if PFWL_USE_INLINING == 1
    inline
#endif
#endif
    void
    pfwl_ipv6_fragmentation_delete_source(pfwl_ipv6_fragmentation_state_t *state,
                                          pfwl_ipv6_fragmentation_source_t *source) {
  uint16_t row = source->row;

  /** Delete all the flows belonging to this source. **/
  pfwl_ipv6_fragmentation_flow_t *flow = source->flows, *temp_flow;
  while (flow) {
    temp_flow = flow->next;
    pfwl_ipv6_fragmentation_delete_flow(state, flow);
    flow = temp_flow;
  }

  /** Delete this source from the list. **/
  if (source->prev)
    source->prev->next = source->next;
  else
    state->table[row] = source->next;

  if (source->next)
    source->next->prev = source->prev;

  free(source);
  state->total_used_mem -= sizeof(pfwl_ipv6_fragmentation_source_t);
}

unsigned char *pfwl_reordering_manage_ipv6_fragment(pfwl_ipv6_fragmentation_state_t *state,
                                                    const unsigned char *unfragmentable_start,
                                                    uint16_t unfragmentable_size,
                                                    const unsigned char *fragmentable_start, uint16_t fragmentable_size,
                                                    uint16_t offset, uint8_t more_fragments, uint32_t identification,
                                                    uint8_t next_header, uint32_t current_time, int) {
  pfwl_ipv6_fragmentation_source_t *source;
  pfwl_ipv6_fragmentation_flow_t *flow;

  struct ip6_hdr ip6_copy;
  memcpy(&ip6_copy, unfragmentable_start, sizeof(ip6_copy));
/**
 * Host are required to do not fragment datagrams with a total size
 * up to 576 byte. If we received a fragment with a size <576 it is
 * maybe a forged fragment used to make an attack. We do this check
 * only in non-debug situations because many of the test used to
 * validate the ip reassembly contains small packets.
 */
#ifndef PFWL_DEBUG_FRAGMENTATION_v6
  if (unlikely(fragmentable_start + fragmentable_size - unfragmentable_start < PFWL_IPv6_FRAGMENTATION_MINIMUM_MTU)) {
    return NULL;
  }
#endif

  /** (end-1) is the last byte of the fragment. **/
  uint32_t end = offset + fragmentable_size;

  /* Attempt to construct an oversize packet. */
  if (unlikely(end > PFWL_IP_FRAGMENTATION_MAX_DATAGRAM_SIZE)) {
    debug_print("%s\n", "Attempt to build an oversized packet");
    return NULL;
  }

#if PFWL_THREAD_SAFETY_ENABLED == 1
  ff::spin_lock(state->lock);
#endif
  source = pfwl_ipv6_fragmentation_find_or_create_source(state, ip6_copy.ip6_src);

  if (unlikely(source == NULL)) {
    debug_print("%s\n", "ERROR: Impossible to create the source. "
                        "Memory exhausted.");
#if PFWL_THREAD_SAFETY_ENABLED == 1
    ff::spin_unlock(state->lock);
#endif
    return NULL;
  }
  debug_print("%s\n", "Source found or created.");

  debug_print("Total memory occupied: %u\n", state->total_used_mem);
  debug_print("Source memory occupied: %u\n", state->total_used_mem);

  /**
   * If I exceeded the source limit, then delete flows from that
   * source.
   **/
  while (source->flows && (source->source_used_mem) > state->per_source_memory_limit) {
    debug_print("%s\n", "Source limit exceeded, cleaning...");
    pfwl_ipv6_fragmentation_delete_flow(state, source->flows);
    if (source->flows == NULL) {
      pfwl_ipv6_fragmentation_delete_source(state, source);
#if PFWL_THREAD_SAFETY_ENABLED == 1
      ff::spin_unlock(state->lock);
#endif
      return NULL;
    }
  }

  /**
   * Control on global memory limit for ip fragmentation.
   * The timer are sorted for the one which will expire sooner to the
   * last that will expire. The loop stops when there are no more
   * expired timers. pfwl_ipv4_fragmentation_delete_flow(..) update
   * the timer timer_head after deleting the timer_head if it is
   * expired.
   **/
  while ((state->timer_head) && ((state->timer_head->expiration_time < current_time) ||
                                 (state->total_used_mem >= state->total_memory_limit))) {
    pfwl_ipv6_fragmentation_source_t *tmpsource = ((pfwl_ipv6_fragmentation_flow_t *) state->timer_head->data)->source;
    pfwl_ipv6_fragmentation_delete_flow(state, (pfwl_ipv6_fragmentation_flow_t *) state->timer_head->data);
    if (source->flows == NULL) {
      pfwl_ipv6_fragmentation_delete_source(state, tmpsource);
#if PFWL_THREAD_SAFETY_ENABLED == 1
      ff::spin_unlock(state->lock);
#endif
      return NULL;
    }
  }

  /* Find the flow. */
  flow = pfwl_ipv6_fragmentation_find_or_create_flow(state, source, identification, ip6_copy.ip6_dst, current_time);

  if (unlikely(flow == NULL)) {
    debug_print("%s\n", "ERROR: Impossible to create the flow.");
#if PFWL_THREAD_SAFETY_ENABLED == 1
    ff::spin_unlock(state->lock);
#endif
    return NULL;
  }

  debug_print("%s\n", "Flow found or created.");

  /**
   * If is a malformed fragment which starts after the end of
   * the entire datagram.
   **/
  if (unlikely(flow->len != 0 && offset > flow->len)) {
#if PFWL_THREAD_SAFETY_ENABLED == 1
    ff::spin_unlock(state->lock);
#endif
    return NULL;
  }

  /*
   * The unfragmentable part is the same for all the fragments. So,
   * differently from IPv4, we don't have to check that the offset is
   * zero to store it but only that it is not already present.
   */
  if (flow->unfragmentable == NULL) {
    flow->unfragmentable = (unsigned char *) malloc(unfragmentable_size * sizeof(unsigned char));
    if (unlikely(flow->unfragmentable == NULL)) {
      pfwl_ipv6_fragmentation_delete_flow(state, flow);
#if PFWL_THREAD_SAFETY_ENABLED == 1
      ff::spin_unlock(state->lock);
#endif
      return NULL;
    }
    flow->unfragmentable_length = unfragmentable_size;
    state->total_used_mem += unfragmentable_size;
    source->source_used_mem += unfragmentable_size;
    memcpy(flow->unfragmentable, unfragmentable_start, unfragmentable_size);
    ((struct ip6_hdr *) flow->unfragmentable)->ip6_ctlun.ip6_un1.ip6_un1_nxt = next_header;
  }

  debug_print("More fragments: %d\n", more_fragments);
  /**
   * If is the final fragment, then we know the exact data_length
   * of the original datagram.
   **/
  if (!more_fragments) {
    debug_print("%s\n", "Last fragment received.");
    /**
     * If the data with MF flag=0 was already received then this
     * fragment is useless.
     **/
    if (flow->len != 0) {
#if PFWL_THREAD_SAFETY_ENABLED == 1
      ff::spin_unlock(state->lock);
#endif
      return NULL;
    }
    flow->len = end;
  }

  uint32_t bytes_removed;
  uint32_t bytes_inserted;
  pfwl_reassembly_insert_fragment(&(flow->fragments), fragmentable_start, offset, end, &bytes_removed, &bytes_inserted);

  state->total_used_mem += bytes_inserted;
  state->total_used_mem -= bytes_removed;

  source->source_used_mem += bytes_inserted;
  source->source_used_mem -= bytes_removed;

  debug_print("%s\n", "Fragment inserted.");

  /**
   *  Check if with the new fragment that we inserted, the original
   *  datagram is now complete. (Only possible if we received the
   *  fragment with MF flag=0 (so the len is set) and if we have a
   *  train of contiguous fragments).
   **/
  if (flow->len != 0 && pfwl_reassembly_ip_check_train_of_contiguous_fragments(flow->fragments)) {
    unsigned char *r;
    debug_print("%s\n", "Last fragment already received and train of "
                        "contiguous fragments present, returing the recompacted "
                        "datagram.");
    r = pfwl_ipv6_fragmentation_build_complete_datagram(state, flow);
#if PFWL_THREAD_SAFETY_ENABLED == 1
    ff::spin_unlock(state->lock);
#endif
    return r;
  }
#if PFWL_THREAD_SAFETY_ENABLED == 1
  ff::spin_unlock(state->lock);
#endif
  return NULL;
}
