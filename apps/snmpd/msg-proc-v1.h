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
 *         Message Processing Model for SNMPv1
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */

#ifndef __MSG_PROC_V1_H__
#define	__MSG_PROC_V1_H__

#include "snmp.h"

#if ENABLE_SNMPv1

/**
 * Takes the input SNMPv1 message as an array of bytes and decodes it to the message_t structure.
 * \brief Decodes a BER encoded SNMP request.
 * \param input     A pointer to a received SNMP in the form of an array of bytes.
 * \param len       Length in bytes of the input.
 * \param pos       The current position in the input.
 * \param request   A poiter to the output message_t data structure.
 * \return 0 - if the processing finishes successfully; otherwise a non-zero value.
 * \hideinitializer
 */
s8t prepareDataElements_v1(u8t* const input, const u16t len, u16t* pos, message_t* request);

/**
 * Takes a pointer to a message_t data structure and produces BER encoded SNMPv1 message based on it.
 * \brief BER encodes an SNMP response.
 * \param message           A pointer to a message_t structure to encode.
 * \param output            A pointer to a buffer where the encoded message should be written.
 * \param output_len        The length of the BER encoded message.
 * \param input             A pointer to the input SNMP request.
 * \param input_len         The length of the input SNMP request.
 * \param max_output_len    The maximum length of the output.
 * \return 0 - if the processing finishes successfully; otherwise a none zero value.
 * \hideinitializer
 */
s8t prepareResponseMessage_v1(message_t* message, u8t* output, u16t* output_len, const u8t* const input, u16t input_len, const u16t max_output_len);

#endif
        
#endif	/* __MSG_PROC_V1_H__ */


