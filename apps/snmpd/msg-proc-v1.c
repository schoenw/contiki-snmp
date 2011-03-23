/* -----------------------------------------------------------------------------
 * SNMP implementation for Contiki
 *
 * Copyright (C) 2010 Siarhei Kuryla <kurilo@gmail.com>
 *
 * This program is part of free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <string.h>

#include "msg-proc-v1.h"
#include "ber.h"
#include "utils.h"
#include "logging.h"
#include "dispatcher.h"

#if ENABLE_SNMPv1

s8t prepareDataElements_v1(u8t* const input, const u16t input_len, u16t* pos, message_t* request) {
    /* decode community string */
    ptr_t community;
    TRY(ber_decode_string((u8t*)input, input_len, pos, &community.ptr, &community.len));

    /* community-based authentication scheme */
    if (request->pdu.error_status == ERROR_STATUS_NO_ERROR &&
            (strlen(COMMUNITY_STRING) != community.len ||
            memcmp(&COMMUNITY_STRING, community.ptr, community.len))) {
        /* the protocol entity notes this failure, (possibly) generates a trap, and discards the datagram
         and performs no further actions. */
        request->pdu.error_status = ERROR_STATUS_GEN_ERR;
        request->pdu.error_index = 0;
        snmp_log("wrong community string (length = %d)\n", request->community.len);
        return 0;
    } else {
        snmp_log("authentication passed\n");
    }

    /* decode the PDU */
    s8t ret = ber_decode_pdu(input, input_len, pos, &request->pdu);
    TRY(ret);

    /* if we ran out of memory send a general error */
    if (ret == ERR_MEMORY_ALLOCATION) {
        request->pdu.error_status = ERROR_STATUS_GEN_ERR;
    } else if (ret != ERR_NO_ERROR) {
        /* if the parsing fails, it discards the datagram and performs no further actions. */
        return FAILURE;
    }
    return 0;
}


/*-----------------------------------------------------------------------------------*/
/*
 * Encode an SNMPv1 response message in BER
 */
static s8t encode_v1_response(const message_t* const message, u8t* output, u16t* output_len, const u8t* const input, u16t input_len, const u16t max_output_len)
{
    s16t pos = max_output_len;
    ber_encode_pdu(output, &pos, input, input_len, &message->pdu, max_output_len);

    /* community string */
    TRY(ber_encode_fixed_string(output, &pos, (u8t*)COMMUNITY_STRING, strlen(COMMUNITY_STRING)));
    /* version */
    TRY(ber_encode_integer(output, &pos, BER_TYPE_INTEGER, message->version));

    /* sequence header*/
    TRY(ber_encode_type_length(output, &pos, BER_TYPE_SEQUENCE, max_output_len - pos));

    *output_len = max_output_len - pos;
    if (pos > 0) {
        memmove(output, output + pos, *output_len);
    }
    return 0;
}

s8t prepareResponseMessage_v1(message_t* message, u8t* output, u16t* output_len, const u8t* const input, u16t input_len, const u16t max_output_len) {
    /* encode the response */
    if (encode_v1_response(message, output, output_len, input, input_len, max_output_len) != ERR_NO_ERROR) {
        /* Too big message.
         * If the size of the GetResponse-PDU generated as described
         * below would exceed a local limitation, then the receiving
         * entity sends to the originator of the received message
         * the GetResponse-PDU of identical form, except that the
         * value of the error-status field is tooBig, and the value
         * of the error-index field is zero.
         */
        message->pdu.error_status = ERROR_STATUS_TOO_BIG;
        message->pdu.error_index = 0;
        if (encode_v1_response(message, output, output_len, input, input_len, max_output_len) == -1) {
            incSilentDrops();
            return FAILURE;
        }
    }
    return 0;
}

#endif