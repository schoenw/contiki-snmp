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
 *         User-based Security Model
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */

#ifndef __USM_H_
#define	__USM_H_

#include "snmp.h"

#if ENABLE_SNMPv3

s8t processIncomingMsg_USM(u8t* const input, const u16t input_len, u16t* pos, message_v3_t* request);

s8t prepareOutgoingMsg_USM(message_v3_t* message, u8t* output, u16t output_len, s16t* pos);

s8t authenticate(message_v3_t* message, u8t* output, u16t output_len);

#endif

#endif	/* __USM_H_ */

