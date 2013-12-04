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
#include <stdlib.h>

#include "usm.h"
#include "ber.h"
#include "utils.h"
#include "logging.h"
#include "keytools.h"
#include "snmpd.h"
#include "snmpd-conf.h"
#include "md5.h"
#include "aes.h"
#if CONTIKI_TARGET_AVR_RAVEN 
#include "sysman.h"
#else
int getSysUpTime() {
  return clock_seconds();
}
#endif

#if !CONTIKI_TARGET_AVR_RAVEN 
#define getSysUptime() clock_time()
#endif

#if ENABLE_SNMPv3

/** \brief The total number of packets received by the SNMP engine
 *         which were dropped because they appeared outside of
 *         the authoritative SNMP engine's window.
 */
u8t usmStatsNotInTimeWindows_array[] = {0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x02, 0x00};
ptr_t usmStatsNotInTimeWindows = {usmStatsNotInTimeWindows_array, 10};
u32t usmStatsNotInTimeWindowsCounter;

/** \brief The total number of packets received by the SNMP
 *         engine which were dropped because they referenced a
 *         user that was not known to the SNMP engine.
 */
u8t usmStatsUnknownUserNames_array[] = {0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x03, 0x00};
ptr_t usmStatsUnknownUserNames = {usmStatsUnknownUserNames_array, 10};
u32t usmStatsUnknownUserNamesCounter;

/** \brief The total number of packets received by the SNMP
 *         engine which were dropped because they referenced an
 *         snmpEngineID that was not known to the SNMP engine.
 */
u8t usmStatsUnknownEngineIDs_array[] = {0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x04, 0x00};
ptr_t usmStatsUnknownEngineIDs = {usmStatsUnknownEngineIDs_array, 10};
u32t usmStatsUnknownEngineIDCounter;

/** \brief The total number of packets received by the SNMP
 *         engine which were dropped because they didn't
 *         contain the expected digest value.
 */
u8t usmStatsWrongDigests_array[] = {0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x05, 0x00};
ptr_t usmStatsWrongDigests = {usmStatsWrongDigests_array, 10};
u32t usmStatsWrongDigestsCounter;

/** \brief The total number of packets received by the SNMP
 *         engine which were dropped because they didn't
 *         contain the expected digest value.
 */
u8t usmStatsDecryptionErrors_array[] = {0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x06, 0x00};
ptr_t usmStatsDecryptionErrors = {usmStatsDecryptionErrors_array, 10};
u32t usmStatsDecryptionErrorsCounter;

static s8t decode_USM_parameters(u8t* const input, const u16t input_len, u16t* pos, message_v3_t* request)
{
    u8t  type;
    u16t length;
    /* encoded as a string value */
    TRY(ber_decode_type_length(input, input_len, pos, &type, &length));
    if (type != BER_TYPE_OCTET_STRING) {
        snmp_log("bad type, expected string: type %02X length %d\n", type, length);
        return FAILURE;
    }
    /* sequence */
    TRY(ber_decode_sequence_length(input, input_len, pos, &length));

    /* msgAuthoritativeEngineID */
    TRY(ber_decode_string((u8t*)input, input_len, pos, &request->msgAuthoritativeEngineID.ptr, &request->msgAuthoritativeEngineID.len));

    /* msgAuthoritativeEngineBoots */
    TRY(ber_decode_integer(input, input_len, pos, (s32t*)&request->msgAuthoritativeEngineBoots));

    /* msgAuthoritativeEngineTime */
    TRY(ber_decode_integer(input, input_len, pos, (s32t*)&request->msgAuthoritativeEngineTime));

    /* msgUserName */
    TRY(ber_decode_string((u8t*)input, input_len, pos, &request->msgUserName.ptr, &request->msgUserName.len));

    /* msgAuthenticationParameters */
    TRY(ber_decode_string((u8t*)input, input_len, pos, &request->msgAuthenticationParameters.ptr, &request->msgAuthenticationParameters.len));

    /* msgPrivacyParameters */
    TRY(ber_decode_string((u8t*)input, input_len, pos, &request->msgPrivacyParameters.ptr, &request->msgPrivacyParameters.len));

    if (request->msgFlags & FLAG_PRIV) {
        TRY(ber_decode_type_length((u8t*)input, input_len, pos, &type, &length));
        if (type != BER_TYPE_OCTET_STRING || length != input_len - *pos) {
            return FAILURE;
        }
    }
    return 0;
}

static s8t report(message_v3_t* request, ptr_t* oid, u32t* counter) {
    (*counter)++;
    if (!(request->msgFlags & FLAG_REPORTABLE)) {
        /* if the reportable flag is not set, then don't send a Report PDU */
        return FAILURE;
    }
    // release variable bindings from the PDU
    free_varbinds(&request->pdu);

    request->msgFlags = 0;
    request->pdu.response_type = BER_TYPE_SNMP_REPORT;
    
    request->pdu.varbind_first_ptr = varbind_list_append(0);
    if (!request->pdu.varbind_first_ptr) {
        return FAILURE;
    }
    request->pdu.varbind_first_ptr->varbind.oid_ptr = oid;
    request->pdu.varbind_first_ptr->varbind.value_type = BER_TYPE_COUNTER;
    request->pdu.varbind_first_ptr->varbind.value.u_value = *counter;
    return 0;
}

#if ENABLE_AUTH
static void hmac_md5_96(u8t* input, u16t input_len, u8t* hmac)
{
    u8t i;
    /* get ipad */
    u8t pad[64];
    memset(pad, 0, 64);
    memcpy(pad, getAuthKul(), 16);
    for (i = 0; i < 64; i++) {
        pad[i] ^= 0x36;
    }

    MD5_CTX MD;
    MD5Init (&MD);
    MD5Update (&MD, pad, 64);
    MD5Update (&MD, input, input_len);
    MD5Final (&MD, hmac);

    /* get opad */
    memset(pad, 0, 64);
    memcpy(pad, getAuthKul(), 16);
    for (i = 0; i < 64; i++) {
        pad[i] ^= 0x5C;
    }

    MD5Init (&MD);
    MD5Update (&MD, pad, 64);
    MD5Update (&MD, hmac, 16);
    MD5Final (&MD, hmac);
}

/*
 *  Checks HMAC-MD5-96.
 */
static s8t isBadHMAC(u8t* input, u16t input_len, message_v3_t* request)
{
    u8t authParam[12];
    memcpy(authParam, request->msgAuthenticationParameters.ptr, 12);
    memset(request->msgAuthenticationParameters.ptr, 0, 12);

    u8t hmac[16];
    hmac_md5_96(input, input_len, hmac); 

    if (memcmp(authParam, hmac, 12)) {
        snmp_log("authentication failed\n");
        return ERR_USM;
    }
    return 0;
}
#endif

#if ENABLE_PRIVACY
/*-----------------------------------------------------------------------------------*/
static s8t aes_process(u8t* key, u8t* iv, u8t* input, u8t* output, u16t len, u8t mode)
{
    AES_KEY aes_key;
    s32t new_ivlen = 0;

    AES_set_encrypt_key(key, &aes_key);
    AES_cfb128_encrypt(input, output, len, &aes_key, iv, &new_ivlen, mode);
    return 0;
}
#endif

s8t processIncomingMsg_USM(u8t* const input, const u16t input_len, u16t* pos, message_v3_t* request)
{
    /* If the value of the msgAuthoritativeEngineID field in the securityParameters is unknown, return usmStatsUnknownEngineIDs */
    TRY(decode_USM_parameters(input, input_len, pos, request));

    if (request->msgAuthoritativeEngineID.len != getEngineID()->len ||
            memcmp(request->msgAuthoritativeEngineID.ptr, getEngineID()->ptr, getEngineID()->len)) {
        TRY(report(request, &usmStatsUnknownEngineIDs, &usmStatsUnknownEngineIDCounter));
        return ERR_USM;
    }

    /* check user name */
    if (request->msgUserName.len != strlen((char*)getUserName()) || memcmp(request->msgUserName.ptr, getUserName(), request->msgUserName.len) != 0) {
        TRY(report(request, &usmStatsUnknownUserNames, &usmStatsUnknownUserNamesCounter));
        return ERR_USM;
    }

    if (request->msgFlags & FLAG_AUTH) {
#if ENABLE_AUTH
        /* The timeliness check is only performed if authentication is applied to the message */
        if (request->msgAuthenticationParameters.len != 12 || isBadHMAC(input, input_len, request) != ERR_NO_ERROR) {
            TRY(report(request, &usmStatsWrongDigests, &usmStatsWrongDigestsCounter));
            return ERR_USM;
        }
#else
        return FAILURE;
#endif
    }

    if (request->msgAuthoritativeEngineBoots != getMsgAuthoritativeEngineBoots() || 
            abs(request->msgAuthoritativeEngineTime - getSysUpTime()) < TIME_WINDOW) {
        TRY(report(request, &usmStatsNotInTimeWindows, &usmStatsNotInTimeWindowsCounter));
        return ERR_USM;
    }

    if (request->msgFlags & FLAG_PRIV) {
#if ENABLE_PRIVACY
        if (request->msgPrivacyParameters.len != 8) {
            TRY(report(request, &usmStatsDecryptionErrors, &usmStatsDecryptionErrorsCounter));
            return ERR_USM;
        }
        /* init IV */
        u8t iv[16];
        convert_2_octets(iv, request->msgAuthoritativeEngineBoots);
        convert_2_octets(iv + 4, request->msgAuthoritativeEngineTime);
        memcpy(iv + 8, request->msgPrivacyParameters.ptr, 8);
        /* decode the Scoped PDU */
        aes_process(getPrivKul(), iv, input + *pos, input + *pos, input_len - *pos, AES_DECRYPT);
#else
        return FAILURE;
#endif
    }
    return 0;
}

static s8t encode_USM_parameters(message_v3_t* message, u8t* output, u16t buf_len, s16t* pos) {
    if (message->msgFlags & FLAG_PRIV) {
#if ENABLE_PRIVACY
        u8t iv[16];
        /* IV */
        convert_2_octets(iv, message->msgAuthoritativeEngineBoots);
        convert_2_octets(iv + 4, message->msgAuthoritativeEngineTime);
        /* privace parameters */
        convert_2_octets(message->msgPrivacyParameters.ptr, getLPrivacyParameters());
        convert_2_octets(message->msgPrivacyParameters.ptr, getHPrivacyParameters());
        memcpy(iv + 8, message->msgPrivacyParameters.ptr, 8);
        aes_process(getPrivKul(), iv, output + *pos, output + *pos, buf_len - *pos, AES_ENCRYPT);
        TRY(ber_encode_type_length(output, pos, BER_TYPE_OCTET_STRING, buf_len - *pos));
#else
        return FAILURE;
#endif
    }

    s16t tmpPos = *pos;
    TRY(ber_encode_fixed_string(output, pos, message->msgPrivacyParameters.ptr, message->msgPrivacyParameters.len));

    TRY(ber_encode_fixed_string(output, pos, message->msgAuthenticationParameters.ptr, message->msgAuthenticationParameters.len));
    message->msgAuthenticationParameters.ptr = &output[*pos + 2];

    TRY(ber_encode_fixed_string(output, pos, message->msgUserName.ptr, message->msgUserName.len));

    TRY(ber_encode_integer(output, pos, BER_TYPE_INTEGER, message->msgAuthoritativeEngineTime));

    TRY(ber_encode_integer(output, pos, BER_TYPE_INTEGER, message->msgAuthoritativeEngineBoots));

    TRY(ber_encode_fixed_string(output, pos, message->msgAuthoritativeEngineID.ptr, message->msgAuthoritativeEngineID.len));

    TRY(ber_encode_type_length(output, pos, BER_TYPE_SEQUENCE, tmpPos - *pos));

    TRY(ber_encode_type_length(output, pos, BER_TYPE_OCTET_STRING, tmpPos - *pos));

    return 0;
}

s8t prepareOutgoingMsg_USM(message_v3_t* message, u8t* output, u16t output_len, s16t* pos)
{
    memcpy(&message->msgAuthoritativeEngineID, getEngineID(), sizeof(ptr_t));
    message->msgAuthoritativeEngineBoots    = getMsgAuthoritativeEngineBoots();
    message->msgAuthoritativeEngineTime     = getSysUpTime()/100;

    encode_USM_parameters(message, output, output_len, pos);
    return 0;
}

s8t authenticate(message_v3_t* message, u8t* output, u16t output_len)
{
#if ENABLE_AUTH
    u8t hmac[16];
    hmac_md5_96(output, output_len, hmac);
    memcpy(message->msgAuthenticationParameters.ptr, hmac, 12);
#endif
    return 0;
}
#endif
