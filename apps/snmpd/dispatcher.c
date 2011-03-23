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

#include <stdlib.h>
#include <string.h>

#include "dispatcher.h"
#include "ber.h"
#include "logging.h"
#include "utils.h"
#include "cmd-responder.h"

#if ENABLE_SNMPv1
#include "msg-proc-v1.h"
#endif

#if ENABLE_SNMPv3
#include "msg-proc-v3.h"
#endif

/** \brief The total number of messages delivered to the SNMP entity from the transport service. */
u32t snmpInPkts = 0;
/** \brief The total number of SNMP messages which were delivered to the SNMP entity and were for an unsupported SNMP version. */
u32t snmpInBadVersions = 0;
/** \brief The total number of ASN.1 or BER errors encountered by the SNMP entity when decoding received SNMP messages. */
u32t snmpInASNParseErrs = 0;
/** \brief */
u32t snmpSilentDrops = 0;

u32t getSnmpInPkts()
{
    return snmpInPkts;
}

u32t getSnmpInBadVersions()
{
    return snmpInBadVersions;
}

u32t getSnmpInASNParseErrs()
{
    return snmpInASNParseErrs;
}

u32t getSnmpSilentDrops()
{
    return snmpSilentDrops;
}

void incSilentDrops()
{
    snmpSilentDrops++;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Handle an SNMP request
 */
s8t dispatch(u8t* const input,  const u16t input_len, u8t* output, u16t* output_len, const u16t max_output_len)
{
    snmpInPkts++;
    snmp_log("---------------------------------\n");
    
    /* too big incoming message */
    if (input_len > MAX_BUF_SIZE) {
        snmp_log("discard the message, its size [%d] is too big\n", input_len);
        return FAILURE;
    }
    
    u16t pos = 0;
    s32t tmp;

    /* decode sequence & version */
    if ((ber_decode_sequence(input, input_len, &pos)) != ERR_NO_ERROR ||
        ber_decode_integer(input, input_len, &pos, &tmp) != ERR_NO_ERROR) {
        snmpInASNParseErrs++;
        return FAILURE;
    }

    /* create the right message_t data structure */
    message_t* msg_ptr;    
    switch (tmp) {
#if ENABLE_SNMPv1
        case SNMP_VERSION_1:
            msg_ptr = malloc(sizeof(message_t));
            memset(msg_ptr, 0, sizeof(message_t));
            break;
#endif
#if ENABLE_SNMPv3
        case SNMP_VERSION_3:
            msg_ptr = malloc(sizeof(message_v3_t));
            memset(msg_ptr, 0, sizeof(message_v3_t));
            break;
#endif
        default:
            /* If the version is not supported, it discards the datagram and performs no further actions. */
            snmpInBadVersions++;
            snmp_log("unsupported SNMP version %d\n", tmp);
            return ERR_UNSUPPORTED_VERSION;
    }
    msg_ptr->version = (u8t)tmp;
    snmp_log("snmp version: %d\n", msg_ptr->version);

    /* dispatch processing to the version-specific Message Processing Model */
    switch (msg_ptr->version) {
#if ENABLE_SNMPv1
        case SNMP_VERSION_1:
            tmp = prepareDataElements_v1(input, input_len, &pos, (message_t*)msg_ptr);
            break;
#endif
#if ENABLE_SNMPv3
        case SNMP_VERSION_3:
            tmp = prepareDataElements_v3(input, input_len, &pos, (message_v3_t*)msg_ptr);
            break;
#endif
    }
    if (tmp != ERR_NO_ERROR) {
        snmpInASNParseErrs++;
        free_message(msg_ptr);
        return FAILURE;
    }

    /* delegate request processing to the Command Responder */
    handle(msg_ptr);

    /* dispatch preparing the response to the version-specific Message Processing Model */
    switch (msg_ptr->version) {
#if ENABLE_SNMPv1
        case SNMP_VERSION_1:
            tmp = prepareResponseMessage_v1((message_t*)msg_ptr, output, output_len, input, input_len, max_output_len);
            break;
#endif
#if ENABLE_SNMPv3
        case SNMP_VERSION_3:
            tmp = prepareResponseMessage_v3((message_v3_t*)msg_ptr, output, output_len, input, input_len, max_output_len);
            break;
#endif
    }
    free_message(msg_ptr);
    if (tmp != ERR_NO_ERROR) {
        return FAILURE;
    }
    return 0;
}