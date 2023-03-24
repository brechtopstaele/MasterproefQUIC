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

void ja3_parse_supported_groups(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private,
 unsigned char *ja3_supgrps_string, size_t *ja3_supgrps_string_len) {
	size_t		pointer = 0;
	size_t 		TLVlen 	= 0;

	size_t grps_len = ntohs(*(uint16_t *)(&data[pointer]));
	pointer += 2;

	for (pointer; pointer < grps_len+2; pointer += 2) {
		size_t		supgrp = 0;
		supgrp = ntohs(*(uint16_t *)(&data[pointer]));
	 	*ja3_supgrps_string_len += sprintf(ja3_supgrps_string + *ja3_supgrps_string_len, "%u-", supgrp);
	}

}

void ja3_parse_extensions(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, 
	unsigned char *ja3_string, size_t *ja3_string_len, unsigned char *ja3_supgrps_string, size_t *ja3_supgrps_string_len) {
	size_t pointer;
	size_t TLVlen;

	for (pointer = 0; pointer < len; pointer += TLVlen) {
		size_t TLVtype = ntohs(*(uint16_t *)(&data[pointer]));
		pointer += 2;
		TLVlen = ntohs(*(uint16_t *)(&data[pointer]));
		pointer += 2;

		switch(TLVtype) {
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

			/* supported_groups */
			case 10:
				ja3_parse_supported_groups(state, data + pointer, TLVlen, pkt_info, flow_info_private, ja3_supgrps_string, ja3_supgrps_string_len);
				break; 
			default:
				break;
		}	
		*ja3_string_len += sprintf(ja3_string + *ja3_string_len, "%u-", TLVtype);

	}
	if (len) {
		*ja3_string_len = *ja3_string_len - 1; //remove last dash (-) from ja3_string
	}
}

size_t parse_ja3_string(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info,
 pfwl_flow_info_private_t *flow_info_private, unsigned char *ja3_string, uint16_t tls_version){
    /*JA3 Finger printing 
      Documentation:
      https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/
    */

    size_t pointer = 0;
	size_t ja3_string_len;

	unsigned char ja3_supgrps_string[100];
	size_t ja3_supgrps_string_len = 0;

	/* Build JA3 string */
	ja3_string_len = sprintf(ja3_string, "%d,", tls_version);

	/* Cipher suites and length */
	uint16_t cipher_suite_len = ntohs(*(uint16_t *)(&data[pointer]));
	pointer += 2;

	/* use content of cipher suite for building the JA3 hash */
    for (size_t i = 0; i < cipher_suite_len; i += 2) {
        uint16_t cipher_suite = ntohs(*(uint16_t *)(data + pointer + i));
        if(is_grease(cipher_suite)) {
            continue; // skip grease value
        }
    }
    if (cipher_suite_len) {
        ja3_string_len--; //remove last dash (-) from ja3_string
    }
    ja3_string_len += sprintf(ja3_string + ja3_string_len, ",");
    pointer += cipher_suite_len;

    /* compression methods length */
    size_t compression_methods_len = data[pointer];
    pointer++;

    /* Skip compression methods */
    pointer += compression_methods_len;

    /* Extension length */
    uint16_t ext_len = ntohs(*(uint16_t *)(&data[pointer]));
    pointer += 2;

    /* Add Extension length to the ja3 string */
    unsigned const char *ext_data = data + pointer;

    /* lets iterate over the exention list */
    ja3_parse_extensions(state, ext_data, ext_len, pkt_info, flow_info_private, ja3_string, &ja3_string_len, ja3_supgrps_string, &ja3_supgrps_string_len);
    ja3_string_len += sprintf(ja3_string + ja3_string_len, ",");

    /* add supported groups to JA3 string */
    ja3_string_len += sprintf(ja3_string + ja3_string_len, ja3_supgrps_string);
    if(ja3_supgrps_string_len){
        ja3_string_len--; //Remove last dash from supported groups string
    }
    ja3_string_len += sprintf(ja3_string + ja3_string_len, ",");
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
				unsigned char content[TLVlen];
				memcpy(content, data+pointer, TLVlen);
				/*for(int i = 0; i<TLVlen; i++) {
					sprintf(content + i, "%1x", *data + pointer + i);
				}*/
				unsigned char *a = content;
				int num = 0;
				do {
					int b = *a=='1'?1:0;
					num = (num<<1)|b;
					a++;
				} while (*a);
				printf("HEX string content: %02x \n", num);
                //*joy_string_len += sprintf(joy_string + *joy_string_len, "(%04x%04x%s)", TLVtype, TLVlen, content);
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

void npf_qtp(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, 
unsigned char *npf_string, size_t *npf_string_len) {
	size_t		pointer = 0;
	size_t 		TLVlen 	= 0;
	for (pointer = 0; pointer <len; pointer += TLVlen) {
		size_t		TLVtype = 0;
		pointer += quic_get_variable_len(data, pointer, &TLVtype);
		TLVlen = data[pointer];
		pointer++;
		//printf("parameter TLV %08X TLV Size %02d\n", TLVtype, TLVlen);

		size_t content = 0;
		content = ntohs(*(uint16_t *)(&data[pointer]));
		//printf("(%04x%04x%0.2x)", TLVtype, TLVlen, content);
		//*npf_string_len += sprintf(npf_string + *npf_string_len, "(%04x%04x%0.2x)", TLVtype, TLVlen, content);
	}
}

void npf_parse_extensions(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, 
	unsigned char *npf_string, size_t *npf_string_len) {
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
                *npf_string_len += sprintf(npf_string + *npf_string_len, "(0a0a)");
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
				unsigned char *data[TLVlen];
				for(int i = 0; i<TLVlen; i++) {
					sprintf(data + i, "%1x");
				}
                *npf_string_len += sprintf(npf_string + *npf_string_len, "(%04x%04x%s)", TLVtype, TLVlen, data);
                break;
			}

			//TODO: lexographic sorting of extensions

			/* QUIC transport parameters */
			case 0x0039:
			case 0xffa5:
				*npf_string_len += sprintf(npf_string + *npf_string_len, "((%02x)[", TLVtype);
				npf_qtp(state, data + pointer, TLVlen, pkt_info, flow_info_private, npf_string, &npf_string_len);
				*npf_string_len += sprintf(npf_string + *npf_string_len, "])");
				break;

			default:
				*npf_string_len += sprintf(npf_string + *npf_string_len, "(%04x%04x)", TLVtype, TLVlen);
				break;
		}	
	}
}

size_t parse_npf_string(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, unsigned char *npf_string,
 uint16_t tls_version, uint16_t quic_version){
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

	/* use content of cipher suite for building the JA3 hash */
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

    /* Add Extension length to the ja3 string */
    unsigned const char *ext_data = data + pointer;

    /* lets iterate over the exention list */
    npf_parse_extensions(state, ext_data, ext_len, pkt_info, flow_info_private, npf_string, &npf_string_len);
    npf_string_len += sprintf(npf_string + npf_string_len, "]");
	return npf_string_len;
}

char* parse_ja3_hash(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, unsigned char *ja3_string, size_t *ja3_string_len){
	char *md5sum = state->scratchpad + state->scratchpad_next_byte;
	size_t md5sum_len = md5_digest_message(ja3_string, ja3_string_len, md5sum);
        
	pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_QUIC_JA3, md5sum, md5sum_len);
        state->scratchpad_next_byte += md5sum_len;

	//printf("JA3:");
	//debug_print_rawfield(md5sum, 0, md5sum_len);
};

char* parse_joy_hash(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, unsigned char *joy_string, size_t *joy_string_len){
	char *sha256sum = state->scratchpad + state->scratchpad_next_byte;
	size_t sha256sum_len = sha256_digest_message(joy_string, joy_string_len, sha256sum);
};

char* parse_npf_hash(pfwl_state_t *state, const unsigned char *data, size_t len, pfwl_dissection_info_t *pkt_info, pfwl_flow_info_private_t *flow_info_private, unsigned char *npf_string, size_t *npf_string_len){
	char *sha256sum = state->scratchpad + state->scratchpad_next_byte;
	size_t sha256sum_len = sha256_digest_message(npf_string, npf_string_len, sha256sum);
};