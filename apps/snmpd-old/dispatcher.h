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
 *         Implementation of the SNMP protocol.
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */

#ifndef __SNMP_PROTOCOL_H__
#define	__SNMP_PROTOCOL_H__

#include "snmp.h"

/**
 * Dispatches an incoming SNMP request.
 * \brief Handles an incoming SNMP request.
 * \param input             A buffer where a BER encoded SNMP request it stored.
 * \param input_len         The length of the BER encoded SNMP request in the input buffer.
 * \param output            A pointer to a buffer for the constructed SNMP response.
 * \param output_len        The length of the BER encoded SNMP response.
 * \param max_output_len    The length of the output buffer.
 * \return zero value if finished sucessfully, otherwise the code of the error
 */
s8t dispatch(u8t* const input, const u16t input_len, u8t* output, u16t* output_len, const u16t max_output_len);

/**
 * \brief The total number of messages delivered to the SNMP entity from the transport service.
 */
u32t getSnmpInPkts();

/**
 * \brief The total number of SNMP messages which were delivered to the SNMP entity and were for an unsupported SNMP version.
 */
u32t getSnmpInBadVersions();

/**
 * \brief The total number of SNMP messages which were delivered to the SNMP entity and were for an unsupported SNMP version.
 */
u32t getSnmpInASNParseErrs();

/**
 * \brief The total number of dropped messages.
 */
u32t getSnmpSilentDrops();

/**
 * \brief Adds one to the total number of dropped messages.
 */
void incSilentDrops();

#endif	/* __SNMP_PROTOCOL_H__ */

