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

/**
 * \file
 *         Defines an SNMP agent process.
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */


#ifndef __SNMPD_H__
#define __SNMPD_H__

#include "contiki-net.h"
#include "snmpd-types.h"

/** \brief port listened by the SNMP agent */
// port 161 seems to be blocked on our firewall
#define LISTEN_PORT 1610
uint32_t snmp_packets;

/** \brief SNMP agent process. */
PROCESS_NAME(snmpd_process);

/** \brief Time in seconds since the system started. */
//u32t getSysUpTime();

#endif /* __SNMPD_H__ */
