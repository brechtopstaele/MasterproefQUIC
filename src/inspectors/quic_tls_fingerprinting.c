/*
 * quic_tls_fingerprinting.c
 *
 * TLS 1.3 fingerprinting
 *
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 * Copyright (c) 2020 SoftAtHome (david.cluytens@gmail.com)
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

#include <peafowl/inspectors/inspectors.h>
#include <peafowl/peafowl.h>


#include <openssl/bio.h>
#include <openssl/evp.h>
#include "quic_tls_fingerprinting.h"
#include "quic_tls13.h"
#include "quic_utils.h"
#include "quic_ssl_utils.h"
#include <stdbool.h>

#define MAX_EC 512
#define MAX_ECPF 512

/*
 *	 GREASE_TABLE Ref: 
 * 		- https://tools.ietf.org/html/draft-davidben-tls-grease-00
 * 		- https://tools.ietf.org/html/draft-davidben-tls-grease-01
 * 		- https://datatracker.ietf.org/doc/html/rfc8701
 *
 * 	switch grease-table is much faster than looping and testing a lookup grease table 
 *
 */
static unsigned int is_grease(uint32_t x){
	switch(x) {
		case 0x0a0a:
		case 0x1a1a:
		case 0x2a2a:
		case 0x3a3a:
		case 0x4a4a:
		case 0x5a5a:
		case 0x6a6a:
		case 0x7a7a:
		case 0x8a8a:
		case 0x9a9a:
		case 0xaaaa:
		case 0xbaba:
		case 0xcaca:
		case 0xdada:
		case 0xeaea:
		case 0xfafa:
			return 1;
		default:
			return 0;
	}
	return 0;
}

static void parse_ec(const unsigned char *data, const unsigned char *data_end, uint16_t *ec, unsigned int *nbr_ec) {
  // skip len
  data += 2;
  while (data + 1 < data_end && (*nbr_ec < MAX_EC)) {
    uint16_t ec_value = ntohs(get_u16(data, 0));
    ec[*nbr_ec] = ec_value;
    (*nbr_ec)++;
    data += 2;
  }
}

static void parse_ecpf(const unsigned char *data, const unsigned char *data_end, uint8_t *ecpf,
                       unsigned int *nbr_ecpf) {
  // skip len
  data += 1;
  while (data < data_end && (*nbr_ecpf < MAX_ECPF)) {
    uint8_t ecpf_value = *data;
    ecpf[*nbr_ecpf] = ecpf_value;
    (*nbr_ecpf)++;
    data += 1;
  }
}

void ja3_parse_extensions(pfwl_state_t *state, const unsigned char *data, size_t len,
                            pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private,
                            char *ja3_string, size_t *ja3_string_len) {
  size_t pointer;
  size_t TLVlen;

  // list of ext10, ext11 for ja3
  uint16_t ec[MAX_EC];
  uint8_t ecpf[MAX_ECPF];

  unsigned int nbr_ec = 0;
  unsigned int nbr_ecpf = 0;

  for (pointer = 0; pointer < len; pointer += TLVlen) {
    uint16_t TLVtype = ntohs(get_u16(data, pointer));
    pointer += 2;
    TLVlen = ntohs(get_u16(data, pointer));
    pointer += 2;
    // printf("TLV %02d TLV Size %02d\n", TLVtype, TLVlen);

    switch (TLVtype) {
    /* skip grease values */
    case 0x0a0a:
    case 0x1a1a:
    case 0x2a2a:
    case 0x3a3a:
    case 0x4a4a:
    case 0x5a5a:
    case 0x6a6a:
    case 0x7a7a:
    case 0x8a8a:
    case 0x9a9a:
    case 0xaaaa:
    case 0xbaba:
    case 0xcaca:
    case 0xdada:
    case 0xeaea:
    case 0xfafa:
      /* Grease values must be ignored */
      continue;
      break;

      /* Server Name */
    case 0:
      if (pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_QUIC_SNI)) {
        tls13_parse_servername(state, data + pointer, TLVlen, pkt_info, flow_info_private);
      }
      break;
      /* Extension quic transport parameters */
    case 10:
      parse_ec(&data[pointer], &data[pointer + TLVlen], ec, &nbr_ec);
      break;
    case 11:
      parse_ecpf(&data[pointer], &data[pointer + TLVlen], ecpf, &nbr_ecpf);
      break;
    case 65445:
      tls13_parse_quic_transport_params(state, data + pointer, TLVlen, pkt_info, flow_info_private);
      break;
    default:
      break;
    }
    *ja3_string_len += sprintf(ja3_string + *ja3_string_len, "%u-", TLVtype);
  }
  if (len) {
    *ja3_string_len = *ja3_string_len - 1; // remove last dash (-) from ja3_string
  }

  // add ext10
  *ja3_string_len += sprintf(ja3_string + *ja3_string_len, ",");
  for (unsigned int i = 0; i < nbr_ec; ++i) {
    *ja3_string_len += sprintf(ja3_string + *ja3_string_len, "%u-", ec[i]);
  }
  if (nbr_ec) {
    *ja3_string_len = *ja3_string_len - 1; // remove last dash (-) from ja3_string
  }

  // add ext11
  *ja3_string_len += sprintf(ja3_string + *ja3_string_len, ",");
  for (unsigned int i = 0; i < nbr_ecpf; ++i) {
    *ja3_string_len += sprintf(ja3_string + *ja3_string_len, "%u-", ecpf[i]);
  }
  if (nbr_ecpf) {
    *ja3_string_len = *ja3_string_len - 1; // remove last dash (-) from ja3_string
  }
  ja3_string[*ja3_string_len] = '\0';
}

size_t parse_ja3_string(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info,
 pfwl_flow_info_private_t *flow_info_private, unsigned char *ja3_string, uint16_t tls_version){
    /*JA3 Finger printing 
      Documentation:
      https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/
    */

	size_t ja3_string_len;

	size_t pointer = 0;

	/* Build JA3 string */
	ja3_string_len = sprintf(ja3_string, "%d,", tls_version);

	/* Cipher suites and length */
	uint16_t cipher_suite_len = ntohs(get_u16(data, pointer));
	pointer += 2;

	/* use content of cipher suite for building the JA3 hash */
    for (size_t i = 0; i < cipher_suite_len; i += 2) {
        uint16_t cipher_suite = ntohs(get_u16(data, pointer + i));
        if(is_grease(cipher_suite)) {
            continue; // skip grease value
        }
		ja3_string_len += sprintf(ja3_string + ja3_string_len, "%d-", cipher_suite);
    }
    if (cipher_suite_len) {
        ja3_string_len--; // remove last dash (-) from ja3_string
    }
    ja3_string_len += sprintf(ja3_string + ja3_string_len, ",");
    pointer += cipher_suite_len;

    /* compression methods length */
    size_t compression_methods_len = data[pointer];
    pointer++;

    /* Skip compression methods */
    pointer += compression_methods_len;

    /* Extension length */
    uint16_t ext_len = ntohs(get_u16(data, pointer));
    pointer += 2;

    /* Add Extension length to the ja3 string */
    unsigned const char *ext_data = data + pointer;

    /* lets iterate over the exention list */
    ja3_parse_extensions(state, ext_data, ext_len, pkt_info, flow_info_private, ja3_string, &ja3_string_len);

	return ja3_string_len;
}

void joy_parse_extensions(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, 
	unsigned char *joy_string, size_t *joy_string_len) {
	size_t pointer;
	size_t TLVlen;

	for (pointer = 0; pointer < len; pointer += TLVlen) {
		size_t TLVtype = ntohs(*(uint16_t *)(&data[pointer]));
		pointer += 2;
		TLVlen = ntohs(*(uint16_t *)(&data[pointer]));
		pointer += 2;

		switch(TLVtype) {
			/* normalize grease values */
			case 0x0a0a:
			case 0x1a1a:
			case 0x2a2a:
			case 0x3a3a:
            case 0x4a4a:
			case 0x5a5a:
			case 0x6a6a:
			case 0x7a7a:
            case 0x8a8a:
			case 0x9a9a:
			case 0xaaaa:
			case 0xbaba:
            case 0xcaca:
			case 0xdada:
			case 0xeaea:
			case 0xfafa:
				/* Grease values must normalized to 0a0a */
                *joy_string_len += sprintf(joy_string + *joy_string_len, "(0a0a)");
			    break;

			/* supported_groups */
			case 10:
            /* ec_point_formats */
            case 11: 
            /* status_request */
            case 5: 
            /* signature_algoritms */
            case 13: 
            /* application_layer_protocol_negotiation */
            case 16: 
            /* supported_versions */
            case 43: 
            /* psk_key_exchange_modes */
            case 45: {
				*joy_string_len += sprintf(joy_string + *joy_string_len, "(%04x%04x", TLVtype, TLVlen);
				for (int i = 0; i<TLVlen; i+=2) {
					size_t content = ntohs(*(uint16_t *)(&data[pointer+i]));
					*joy_string_len += sprintf(joy_string + *joy_string_len, "%04x", content);
				}
				/* If length of the extension is uneven, remove last extra byte */
				if (TLVlen%2) {
						*joy_string_len -= 2;
					}
				*joy_string_len += sprintf(joy_string + *joy_string_len, ")", TLVtype, TLVlen);
                break;
			}
			default:
				*joy_string_len += sprintf(joy_string + *joy_string_len, "(%04x%04x)", TLVtype, TLVlen);
				break;
		}	
	}
}

size_t parse_joy_string(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, unsigned char *joy_string,
 uint16_t tls_version){
    /*Joy Finger printing 
      Documentation:
      https://github.com/cisco/joy/blob/master/doc/using-joy-fingerprinting-00.pdf
    */

    size_t pointer = 0;
	size_t joy_string_len;

	/* Build Joy string */
	joy_string_len = sprintf(joy_string, "(%04x)(", tls_version);

	/* Cipher suites and length */
	uint16_t cipher_suite_len = ntohs(*(uint16_t *)(&data[pointer]));
	pointer += 2;

	/* use content of cipher suite for building the JA3 hash */
    for (size_t i = 0; i < cipher_suite_len; i += 2) {
        uint16_t cipher_suite = ntohs(*(uint16_t *)(data + pointer + i));
        if(is_grease(cipher_suite)) {
            cipher_suite = 0x0a0a; // normalize grease value
        }
        joy_string_len += sprintf(joy_string + joy_string_len, "%04x", cipher_suite);
    }
    joy_string_len += sprintf(joy_string + joy_string_len, ")(");
    pointer += cipher_suite_len;

    /* compression methods length */
    size_t compression_methods_len = data[pointer];
    pointer++;

    /* Skip compression methods */
    pointer += compression_methods_len;

    /* Extension length */
    uint16_t ext_len = ntohs(*(uint16_t *)(&data[pointer]));
    pointer += 2;

    /* Add Extension length to the joy string */
    unsigned const char *ext_data = data + pointer;

    /* lets iterate over the exention list */
    joy_parse_extensions(state, ext_data, ext_len, pkt_info, flow_info_private, joy_string, &joy_string_len);
    joy_string_len += sprintf(joy_string + joy_string_len, ")");
	return joy_string_len;
}

/* string compare function */
int compare_strings(const void* p1, const void* p2) {
	const char *pp1 = *(const char**)p1;
	const char *pp2 = *(const char**)p2;
	//Skip first '('
	*pp1++;
	*pp2++;
	//Check for Quic transport parameters and skip second '('
	if (*pp1 == '(') {
		*pp1++;
	}
	if (*pp2 == '(') {
		*pp2++;
	}
    return strcmp(pp1, pp2);
}

int find_grease(char* text, int len_text) {
	int pos_text = 0;
	char var = text[pos_text];
	for (pos_text = 1; pos_text < len_text - 3; pos_text++ ) {
		if (text[pos_text] == 'a' && text[pos_text + 1] == var && text[pos_text + 2] == 'a') {
			//match
			return pos_text - 1;
		} else {
			var = text[pos_text];
		}
	}
	//no match
	return 0;
}

/**
 *  @brief QUIC variable length Integer decoding algorithm, returns data including length indications
 */
size_t quic_degrease(const unsigned char *app_data, size_t offset, uint64_t *var_len) {
  size_t mbit = app_data[offset] >> 6;
  size_t len = 0;

  switch (mbit) {
  case 0:
    *var_len = (uint64_t)(app_data[offset] & 0x3F);
	len = 1;
	if (*var_len%31 == 27) {
		*var_len = 27;
	}
	else {
		*var_len = (uint64_t)(app_data[offset] & 0xFF);
	}
    break;
  case 1:
    *var_len = ((uint64_t)(app_data[offset] & 0x3F) << 8) + (uint64_t)(app_data[offset + 1] & 0xFF);
    len = 2;
	if (*var_len%31 == 27) {
		*var_len = 27;
	}
	else {
		*var_len = ((uint64_t)(app_data[offset] & 0xFF) << 8) + (uint64_t)(app_data[offset + 1] & 0xFF);
	}
    break;
  case 2:
    *var_len = ((uint64_t)(app_data[offset] & 0x3F) << 24) + ((uint64_t)(app_data[offset + 1] & 0xFF) << 16) +
               ((uint64_t)(app_data[offset + 2] & 0xFF) << 8) + (uint64_t)(app_data[offset + 3] & 0xFF);
    len = 4;
	if (*var_len%31 == 27) {
		*var_len = 27;
	}
	else {
		*var_len = ((uint64_t)(app_data[offset] & 0xFF) << 24) + ((uint64_t)(app_data[offset + 1] & 0xFF) << 16) +
               	   ((uint64_t)(app_data[offset + 2] & 0xFF) << 8) + (uint64_t)(app_data[offset + 3] & 0xFF);
    
	}
    break;
  case 3:
    *var_len = ((uint64_t)(app_data[offset] & 0x3F) << 56) + ((uint64_t)(app_data[offset + 1] & 0xFF) << 48) +
               ((uint64_t)(app_data[offset + 2] & 0xFF) << 40) + ((uint64_t)(app_data[offset + 3] & 0xFF) << 32) +
               ((uint64_t)(app_data[offset + 4] & 0xFF) << 24) + ((uint64_t)(app_data[offset + 5] & 0xFF) << 16) +
               ((uint64_t)(app_data[offset + 6] & 0xFF) << 8) + (uint64_t)(app_data[offset + 7] & 0xFF);
    len = 8;
	if (*var_len%31 == 27) {
		*var_len = 27;
	}
	else {
		*var_len = ((uint64_t)(app_data[offset] & 0xFF) << 56) + ((uint64_t)(app_data[offset + 1] & 0xFF) << 48) +
				   ((uint64_t)(app_data[offset + 2] & 0xFF) << 40) + ((uint64_t)(app_data[offset + 3] & 0xFF) << 32) +
				   ((uint64_t)(app_data[offset + 4] & 0xFF) << 24) + ((uint64_t)(app_data[offset + 5] & 0xFF) << 16) +
				   ((uint64_t)(app_data[offset + 6] & 0xFF) << 8) + (uint64_t)(app_data[offset + 7] & 0xFF);
	}
    break;
  default:
    len = 0; /* error should not happen */
  }
  return len;
}

void npf_qtp(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, 
unsigned char *extensions, size_t *extensions_len) {
	size_t		pointer = 0;
	size_t 		TLVlen 	= 0;
	const unsigned char* qtp[len/4];
	size_t qtp_len[len/4];
	size_t n = 0;
	

	for (pointer = 0; pointer <len; pointer += TLVlen) {
		//TODO: find max length of quic transport parameter
		qtp[n] = malloc(20);
		qtp_len[n] = 0;

		size_t TLVtype = 0;
		size_t len;
		len = quic_degrease(data, pointer, &TLVtype);
		pointer += len;
		TLVlen = data[pointer];
		pointer++;
		
		/* Check for GREASE */
		qtp_len[n] += sprintf(qtp[n] + qtp_len[n], "(%02x)", TLVtype);
		n++;
	}

	/* lexicographic sorting of quic transport parameters */
	qsort(qtp, n, sizeof(qtp[0]), compare_strings);

	for (uint16_t i = 0; i < n; i++){
        *extensions_len += sprintf (extensions + *extensions_len, qtp[i]);
		free(qtp[i]);
	}
	*extensions_len += sprintf(extensions + *extensions_len, "])");

}

void npf_parse_extensions(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, 
	unsigned char *npf_string, size_t *npf_string_len, uint16_t ext_len) {
	size_t pointer;
	size_t TLVlen;
	const unsigned char* extensions[ext_len/4];
	size_t extensions_len[ext_len/4];
	size_t n = 0;

	for (pointer = 0; pointer < len; pointer += TLVlen) {
		size_t TLVtype = ntohs(*(uint16_t *)(&data[pointer]));
		pointer += 2;
		TLVlen = ntohs(*(uint16_t *)(&data[pointer]));
		pointer += 2;

		//TODO: find max length of extension
		extensions[n] = malloc(200);
		extensions_len[n] = 0;

		switch(TLVtype) {
			/* normalize grease values */
			case 0x0a0a:
			case 0x1a1a:
			case 0x2a2a:
			case 0x3a3a:
            case 0x4a4a:
			case 0x5a5a:
			case 0x6a6a:
			case 0x7a7a:
            case 0x8a8a:
			case 0x9a9a:
			case 0xaaaa:
			case 0xbaba:
            case 0xcaca:
			case 0xdada:
			case 0xeaea:
			case 0xfafa:
				/* Grease values must normalized to 0a0a */
                extensions_len[n] += sprintf(extensions[n] + extensions_len[n], "(0a0a)");
			    break;

			/* TLS_EXT_FIXED */
			case 0x0001:
			case 0x0005:
			case 0x0007:
			case 0x0008:
			case 0x0009:
			case 0x000a:
			case 0x000b:
			 case 0x000d:
			case 0x000f:
			case 0x0010:
			case 0x0011:
			case 0x0018:
			case 0x001b:
			case 0x001c:
			 case 0x002b:
			 case 0x002d:
			case 0x0032:
			case 0x5500:
			{
				extensions_len[n] += sprintf(extensions[n] + extensions_len[n], "(%04x%04x", TLVtype, TLVlen);
				for (int i = 0; i<TLVlen; i+=2) {
					size_t content = ntohs(*(uint16_t *)(&data[pointer+i]));
					extensions_len[n] += sprintf(extensions[n] + extensions_len[n], "%04x", content);
				}
				/* If length of the extension is uneven, remove last extra byte */
				if (TLVlen%2) {
					extensions_len[n] -= 2;
					extensions_len[n] += sprintf(extensions[n] + extensions_len[n], ")\0");
				}
				else {
					extensions_len[n] += sprintf(extensions[n] + extensions_len[n], ")");
				}
				int pos = find_grease(extensions[n], extensions_len[n]);
				if (pos) {
					strncpy(extensions[n] + pos, "0a0a", 4);
				}
                break;
			}

			/* TLS_EXT_FIXED with possible GREASE */
			// case 0x000d:
			// {
			// 	extensions_len[n] += sprintf(extensions[n] + extensions_len[n], "(%04x%04x", TLVtype, TLVlen);
			// 	size_t intern_len = ntohs(*(uint16_t *)(&data[pointer]));
			// 	extensions_len[n] += sprintf(extensions[n] + extensions_len[n], "%04x", intern_len);
			// 	for (int i = 2; i<TLVlen; i+=2) {
			// 		size_t content = ntohs(*(uint16_t *)(&data[pointer+i]));
			// 		if (is_grease(content)) {
			// 			content = 0x0a0a;
			// 		}
			// 		extensions_len[n] += sprintf(extensions[n] + extensions_len[n], "%04x", content);
			// 	}
			// 	if (TLVlen%2) {
			// 		extensions_len[n] -= 2;
			// 		extensions_len[n] += sprintf(extensions[n] + extensions_len[n], ")\0");
			// 	}
			// 	else {
			// 		extensions_len[n] += sprintf(extensions[n] + extensions_len[n], ")");
			// 	}
			// }
			// case 0x002b:
			// case 0x002d:
			// {
			// 	extensions_len[n] += sprintf(extensions[n] + extensions_len[n], "(%04x%04x", TLVtype, TLVlen);
			// 	size_t intern_len = ntohs(*(uint8_t *)(&data[pointer]));
			// 	extensions_len[n] += sprintf(extensions[n] + extensions_len[n], "%02x", intern_len);
			// 	for (int i = 1; i<TLVlen; i+=2) {
			// 		size_t content = ntohs(*(uint16_t *)(&data[pointer+i]));
			// 		if (is_grease(content)) {
			// 			content = 0x0a0a;
			// 		}
			// 		extensions_len[n] += sprintf(extensions[n] + extensions_len[n], "%04x", content);
			// 	}
			// 	if (TLVlen%2) {
			// 		extensions_len[n] -= 2;
			// 		extensions_len[n] += sprintf(extensions[n] + extensions_len[n], ")\0");
			// 	}
			// 	else {
			// 		extensions_len[n] += sprintf(extensions[n] + extensions_len[n], ")");
			// 	}
			// }

			/* QUIC transport parameters */
			case 0x0039:
			case 0xffa5:
				extensions_len[n] += sprintf(extensions[n] + extensions_len[n], "((%04x)[", TLVtype);
				npf_qtp(state, data + pointer, TLVlen, pkt_info, flow_info_private, extensions[n], &extensions_len[n]);
				break;

			default:
				extensions_len[n] += sprintf(extensions[n] + extensions_len[n], "(%04x)", TLVtype);
				break;
		}	
		n++;
	}

	qsort(extensions, n, sizeof(extensions[0]), compare_strings);
    
	for (uint16_t i = 0; i < n; i++)
        *npf_string_len += sprintf (npf_string + *npf_string_len, extensions[i]);
}

size_t parse_npf_string(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, unsigned char *npf_string,
 uint16_t tls_version, uint32_t quic_version){
	/*NPF Finger printing 
      Documentation:
      https://github.com/cisco/mercury/blob/main/doc/npf.md
    */

    size_t pointer = 0;
	size_t npf_string_len;

	/* Build NPF string */
	npf_string_len = sprintf(npf_string, "quic/(%08x)(%04x)(", quic_version, tls_version);

	/* Cipher suites and length */
	uint16_t cipher_suite_len = ntohs(*(uint16_t *)(&data[pointer]));
	pointer += 2;

	/* use content of cipher suite for building the NPF string*/
    for (size_t i = 0; i < cipher_suite_len; i += 2) {
        uint16_t cipher_suite = ntohs(*(uint16_t *)(data + pointer + i));
        if(is_grease(cipher_suite)) {
            cipher_suite = 0x0a0a; // normalize grease value
        }
        npf_string_len += sprintf(npf_string + npf_string_len, "%04x", cipher_suite);
    }
    npf_string_len += sprintf(npf_string + npf_string_len, ")[");
    pointer += cipher_suite_len;

    /* compression methods length */
    size_t compression_methods_len = data[pointer];
    pointer++;

    /* Skip compression methods */
    pointer += compression_methods_len;

    /* Extension length */
    uint16_t ext_len = ntohs(*(uint16_t *)(&data[pointer]));
    pointer += 2;

    /* Add Extension length to the npf string */
    unsigned const char *ext_data = data + pointer;

    /* lets iterate over the exention list */
    npf_parse_extensions(state, ext_data, ext_len, pkt_info, flow_info_private, npf_string, &npf_string_len, ext_len);
    npf_string_len += sprintf(npf_string + npf_string_len, "]");
	return npf_string_len;
}

size_t parse_ja3_hash(pfwl_state_t *state, unsigned char *ja3_string, size_t ja3_string_len, char *ja3_start){
	unsigned char md5[16];
    size_t md5sum_len = md5_digest_message((const unsigned char *) ja3_string, ja3_string_len, md5);

    ja3_start = state->scratchpad + state->scratchpad_next_byte;

    for (size_t n = 0; n < md5sum_len; n++) {
      sprintf(state->scratchpad + state->scratchpad_next_byte, "%02x", md5[n]);
      state->scratchpad_next_byte += 2;
    }
	return md5sum_len*2;
};

char* parse_joy_hash(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, unsigned char *joy_string, size_t *joy_string_len){
	char *sha256sum = state->scratchpad + state->scratchpad_next_byte;
	size_t sha256sum_len = sha256_digest_message(joy_string, joy_string_len, sha256sum);
};

char* parse_npf_hash(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, unsigned char *npf_string, size_t *npf_string_len){
	char *sha256sum = state->scratchpad + state->scratchpad_next_byte;
	size_t sha256sum_len = sha256_digest_message(npf_string, npf_string_len, sha256sum);
};