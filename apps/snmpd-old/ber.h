/* -----------------------------------------------------------------------------
 * SNMP implementation for Contiki
 *
 * Copyright (C) 2010 Siarhei Kuryla
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

/**
 * \file
 *         Defines functions for BER encoding and decoding of an SNMP message.
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */

#ifndef __BER_H__
#define	__BER_H__

#include "snmp.h"

/**
 * \defgroup bertypes BER type constants for the ASN.1 implementation of SNMP.
 */
/*@{*/

/** \brief boolean type */
#define BER_TYPE_BOOLEAN                                0x01
/** \brief integer type */
#define BER_TYPE_INTEGER                                0x02
/** \brief bit string type */
#define BER_TYPE_BIT_STRING                             0x03
/** \brief octet string type */
#define BER_TYPE_OCTET_STRING                           0x04
/** \brief null value */
#define BER_TYPE_NULL                                   0x05
/** \brief oid type */
#define BER_TYPE_OID                                    0x06
/** \brief sequence type */
#define BER_TYPE_SEQUENCE                               0x30
/** \brief ip address type */
#define BER_TYPE_IPADDRESS                              0x40
/** \brief counter type */
#define BER_TYPE_COUNTER                                0x41
/** \brief gauge type */
#define BER_TYPE_GAUGE                                  0x42
/** \brief unsigned32 type */
#define BER_TYPE_UNSIGNED32                             BER_TYPE_GAUGE
/** \brief time ticks type */
#define BER_TYPE_TIME_TICKS				0x43
/** \brief opaque type */
#define BER_TYPE_OPAQUE                                 0x44
/** \brief SNMP GET pdu */
#define BER_TYPE_SNMP_GET                               0xA0
/** \brief SNMP GETNEXT pdu */
#define BER_TYPE_SNMP_GETNEXT                           0xA1
/** \brief SNMP RESPONSE */
#define BER_TYPE_SNMP_RESPONSE                          0xA2
/** \brief SNMP SET */
#define BER_TYPE_SNMP_SET                               0xA3
/** \brief SNMP GETBULK */
#define BER_TYPE_SNMP_GETBULK                           0xA5
/** \brief SNMP INFORM */
#define BER_TYPE_SNMP_INFORM                            0xA6
/** \brief SNMP TRAP */
#define BER_TYPE_SNMP_TRAP                              0xA7
/** \brief SNMP REPORT */
#define BER_TYPE_SNMP_REPORT                            0xA8
/** \brief noSuchObject */
#define BER_TYPE_NO_SUCH_OBJECT                         0x80
/** \brief noSuchInstance */
#define BER_TYPE_NO_SUCH_INSTANCE                       0x81
/** \brief endOfMib */
#define BER_TYPE_END_OF_MIB                             0x82

/*@}*/

s8t ber_decode_type_length(const u8t* const input, const u16t len, u16t* pos, u8t* type, u16t* length);

s8t ber_decode_integer(const u8t* const input, const u16t len, u16t* pos, s32t* value);

s8t ber_decode_unsigned_integer(const u8t* const input, const u16t len, u16t* pos, u32t* value);

s8t ber_decode_string(u8t* const input, const u16t len, u16t* pos, u8t** value, u16t* field_len);

s8t ber_decode_sequence(const u8t* const input, const u16t len, u16t* pos);

s8t ber_decode_sequence_length(const u8t* const input, const u16t len, u16t* pos, u16t* length);

s8t ber_decode_oid(u8t* const input, const u16t len, u16t* pos, ptr_t* o);

s8t ber_decode_value(u8t* const input, const u16t len, u16t* pos, u8t* value_type, varbind_value_t* value);

s8t ber_decode_pdu(u8t* const input, const u16t len, u16t* pos, pdu_t* pdu);

/** 
 * \brief Determines the length in bytes of the BER encoded value.
 * \param value     A 32-bit unsigned integer value.
 * \return Length in bytes of the value in the BER encoding.
 * \hideinitializer
 */
u8t ber_encoded_oid_item_length(u32t value);

/**
 * \brief Decodes a BER encoded oid element.
 * \param ptr     A pointer to a buffer where the BER encoded oid element is stored.
 * \param len     Length of the BER encoded buffer.
 * \param value   Value of the BER decoded oid element.
 * \return The length of the BER decoded oid element in the buffer.
 * \hideinitializer
 */
u8t ber_decode_oid_item(u8t* ptr, u8t len, u32t* value);

/**
 * \brief BER encodes an oid element.
 * \param value   Value of the oid element.
 * \param ptr     A pointer to a buffer where the BER encoded oid element should be written.
 * \return 0 - if the processing has successfully finished, otherwise - non-zero value.
 * \hideinitializer
 */
s8t ber_encode_oid_item(u32t value, u8t* ptr);

s8t ber_encode_type_length(u8t* output, s16t* pos, u8t type, u16t len);

s8t ber_encode_integer(u8t* output, s16t* pos, u8t type, const s32t value);

s8t ber_encode_fixed_string(u8t* output, s16t* pos, const u8t* const str_value, const u16t len);

s8t ber_encode_pdu(u8t* output, s16t* pos, const u8t* const input, u16t input_len, const pdu_t* const  pdu, const u16t max_output_len);
#endif	/* __BER_H__ */

