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

#include "logging.h"

#if DEBUG
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/** \brief length of the buffer used for debugging messages */
#define BUF_LEN 100

#if !CONTIKI_TARGET_MINIMAL_NET 
#include "contiki-net.h"

/** \brief port number where debug messages are sent */
#define LOGGING_PORT 12345

/*--------------------------------------------------------------------------*/
/*
 * Log a debug message by sending it within a UDP message.
 */
void snmp_log(char* format, ...)
{  
    static struct uip_udp_conn *udp_con = NULL;
    if (udp_con == NULL) {
        udp_con = udp_new(NULL, UIP_HTONS(LOGGING_PORT), NULL);
        uip_ip6addr(&udp_con->ripaddr, 0xaaaa, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001);
	udp_bind(udp_con, UIP_HTONS(3000));
    }
    
    va_list args;
    va_start(args, format);
    static char buf[BUF_LEN];
    memset(buf, 0, BUF_LEN);
    vsprintf(buf, format, args);
    va_end(args);

    uip_udp_packet_send(udp_con, buf, strlen(buf));
}
#else

void snmp_log(char* format, ... )
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}
#endif /* CONTIKI_TARGET_MINIMAL_NET */
#endif /* DEBUG */


#if INFO
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* length of the buffer used for debugging messages */
#define BUF_LEN 100

#if !CONTIKI_TARGET_MINIMAL_NET
#include "contiki-net.h"

/* port number where debug messages are sent */
#define LOGGING_PORT 12345


/*
 * Log a debug message by sending it within a UDP message.
 */
void snmp_info(char* format, ...)
{
    static struct uip_udp_conn *udp_con = NULL;
    if (udp_con == NULL) {
        udp_con = udp_new(NULL, UIP_HTONS(LOGGING_PORT), NULL);
        uip_ip6addr(&udp_con->ripaddr, 0xaaaa, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001);
	udp_bind(udp_con, UIP_HTONS(3000));
    }

    va_list args;
    va_start(args, format);
    static char buf[BUF_LEN];
    memset(buf, 0, BUF_LEN);
    vsprintf(buf, format, args);
    va_end(args);

    uip_udp_packet_send(udp_con, buf, strlen(buf));
}
#else

void snmp_info(char* format, ... )
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

#endif /* CONTIKI_TARGET_MINIMAL_NET */
#endif /* INFO */
