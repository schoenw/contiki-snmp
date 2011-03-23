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
#include "keytools.h"

#if ENABLE_SNMPv3

#include "snmpd-conf.h"


u8t authKul[16] = {0x6e, 0x53, 0x61, 0xd8, 0xb3, 0xec, 0x95, 0x4f, 0xfb, 0x98, 0x2c, 0x57, 0x45, 0x9e, 0x54, 0x83};

u8t privKul[16] = {0x9f, 0x99, 0x76, 0x2b, 0x85, 0x29, 0xb9, 0x22, 0x70, 0x98, 0x9c, 0xe0, 0xc7, 0x0d, 0xcc, 0x71};

u8t* getAuthKul()
{
    return authKul;
}

u8t* getPrivKul()
{
    return privKul;
}


#endif