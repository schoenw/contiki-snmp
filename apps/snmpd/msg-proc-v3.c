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

#include "snmpd-conf.h"
#include "msg-proc-v3.h"
#include "ber.h"
#include "utils.h"
#include "logging.h"
#include "usm.h"
#include "snmpd.h"

#if ENABLE_SNMPv3

s8t prepareDataElements_v3(u8t* const input, const u16t input_len, u16t* pos, message_v3_t* request)
{
    u8t type;
    u16t length;
    s32t int_value;
    /* msgGlobalData sequence */
    TRY(ber_decode_sequence_length(input, input_len, pos, &length));

    /* msgId */
    TRY(ber_decode_integer(input, input_len, pos, &int_value));
    request->msgId = int_value;
    snmp_log("msgId: %d\n", request->msgId);

    /* msgMaxSize */
    TRY(ber_decode_integer(input, input_len, pos, &int_value));
    snmp_log("msgMaxSize: %d\n", int_value);

    /* msgFlags */
    TRY(ber_decode_type_length(input, input_len, pos, &type, &length));
    if (type != BER_TYPE_OCTET_STRING || length != 1) {
        return FAILURE;
    }
    request->msgFlags = input[*pos];
    *pos = *pos + 1;
    snmp_log("msgFlags: %d\n", request->msgFlags);
    if (!(request->msgFlags & FLAG_AUTH) && (request->msgFlags & FLAG_PRIV)) {
        /* If the authFlag is not set and privFlag is set, then the message is discarded without further processing */
        return FAILURE;
    }

    /* msgSecurityModel */
    TRY(ber_decode_integer(input, input_len, pos, &int_value));
    snmp_log("msgSecurityModel: %d\n", int_value);

    /* treat Security Model */
    s8t ret;
    switch (int_value) {
        case USM_SECURITY_MODEL:
            /* Authentication & Privacy validations */            
            ret = processIncomingMsg_USM(input, input_len, pos, request);
            if (ret == FAILURE) {
                return FAILURE;
            } else if (ret == ERR_USM) {
                /* stop processing this message, a report will be sent */
                return 0;
            }
            break;
        default:
            snmp_log("unsupported security model [%d]\n", request->msgSecurityModel);
            return FAILURE;
    }

    /* ScopedPduData sequence */
    TRY(ber_decode_sequence_length(input, input_len, pos, &length));

    /* contextEngineID */
    TRY(ber_decode_string((u8t*)input, input_len, pos, &request->contextEngineID.ptr, &request->contextEngineID.len));

    /* contextName */
    TRY(ber_decode_string((u8t*)input, input_len, pos, &request->contextName.ptr, &request->contextName.len));

    /* decode PDU */
    ber_decode_pdu(input, input_len, pos, &request->pdu);

    return 0;
}

static s8t encode_v3_response(message_v3_t* message, u8t* output, u16t* output_len, const u8t* const input, u16t input_len, const u16t max_output_len)
{
    s16t pos = max_output_len;
    ber_encode_pdu(output, &pos, input, input_len, &message->pdu, max_output_len);

    TRY(ber_encode_fixed_string(output, &pos, message->contextName.ptr, message->contextName.len));

    TRY(ber_encode_fixed_string(output, &pos, message->contextEngineID.ptr, message->contextEngineID.len));

    TRY(ber_encode_type_length(output, &pos, BER_TYPE_SEQUENCE, max_output_len - pos));

    /* encode Security Model data */
    switch (USM_SECURITY_MODEL) {
        case USM_SECURITY_MODEL:
            TRY(prepareOutgoingMsg_USM(message, output, max_output_len, &pos));
            break;
    }
    /* msgGlobalData sequence */
    s16t tmpPos = pos;
    TRY(ber_encode_integer(output, &pos, BER_TYPE_INTEGER, USM_SECURITY_MODEL));

    /* flags */
    DEC(&pos);
    output[pos] = message->msgFlags;
    TRY(ber_encode_type_length(output, &pos, BER_TYPE_OCTET_STRING, 1));

    TRY(ber_encode_integer(output, &pos, BER_TYPE_INTEGER, MAX_BUF_SIZE));

    TRY(ber_encode_integer(output, &pos, BER_TYPE_INTEGER, message->msgId));

    TRY(ber_encode_type_length(output, &pos, BER_TYPE_SEQUENCE, tmpPos - pos));

    TRY(ber_encode_integer(output, &pos, BER_TYPE_INTEGER, message->version));

    /* sequence header*/
    TRY(ber_encode_type_length(output, &pos, BER_TYPE_SEQUENCE, max_output_len - pos));
    *output_len = max_output_len - pos;
    
    if (message->msgFlags & FLAG_AUTH) {
        authenticate(message, &output[pos], *output_len);
    }
    if (pos > 0) {
        memmove(output, output + pos, *output_len);
    }
    return 0;
}

s8t prepareResponseMessage_v3(message_v3_t* message, u8t* output, u16t* output_len, const u8t* const input, u16t input_len, const u16t max_output_len)
{
    message->msgFlags   &= (FLAG_AUTH | FLAG_PRIV);
    memcpy(&message->contextEngineID, getEngineID(), sizeof(ptr_t));
    
    if (encode_v3_response(message, output, output_len, input, input_len, max_output_len) != ERR_NO_ERROR) {
        // tooBig error
        varbind_list_item_t*  varbind_first_ptr = message->pdu.varbind_first_ptr;
        message->pdu.varbind_first_ptr = 0;
        message->pdu.error_status = ERROR_STATUS_TOO_BIG;
        message->pdu.error_index = 0;
        encode_v3_response(message, output, output_len, input, input_len, max_output_len);
        message->pdu.varbind_first_ptr = varbind_first_ptr;
    }
    return 0;
}

#endif