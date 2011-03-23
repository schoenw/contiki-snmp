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
#include "snmpd-conf.h"

#if ENABLE_SNMPv3

u8t msgAuthoritativeEngineID_array[] = {0x80, 0x00, 0x1f, 0x88, 0x80, 0x77, 0xd5, 0xcb, 0x77, 0x9e, 0xa0, 0xef, 0x4b};
//{0x80, 0x00, 0x39, 0x9b, 0x80, 0x2b, 0x2d, 0x1f, 0x13, 0xc3, 0xc3, 0x96, 0x4b}; // use this engineID

ptr_t msgAuthoritativeEngineID = {msgAuthoritativeEngineID_array, 13};

u8t* usmUserName = (u8t*)"sk";

u32t privacyLow = 0xA6F89012;
u32t privacyHigh = 0xF9434568;

u32t getMsgAuthoritativeEngineBoots()
{
    return 0;
}

u32t getLPrivacyParameters()
{
    privacyLow++;
    return privacyLow;
}

u32t getHPrivacyParameters()
{
    privacyHigh++;
    return privacyHigh;
}

ptr_t* getEngineID()
{
    return &msgAuthoritativeEngineID;
}

u8t* getUserName()
{
    return usmUserName;
}


#endif
