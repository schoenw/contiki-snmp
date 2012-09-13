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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "contiki.h"
#include "contiki-net.h"

#include "snmpd.h"
#include "snmpd-conf.h"
#include "dispatcher.h"
#include "mib-init.h"
#include "logging.h"
#include "keytools.h"

#define UDP_IP_BUF   ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])

/* UDP connection */
static struct uip_udp_conn *udpconn;

PROCESS(snmpd_process, "SNMP daemon process");


#if CONTIKI_TARGET_AVR_RAVEN
extern unsigned long seconds;
#else
clock_time_t systemStartTime;
#endif

/*u32t getSysUpTime()
{
    #if CONTIKI_TARGET_AVR_RAVEN
        return clock_seconds();
	  //return seconds * 100;
    #else
        return (clock_time() - systemStartTime)/ 10;
    #endif
}*/

#if CHECK_STACK_SIZE
int max = 0;
u32t* marker;
#endif

/*-----------------------------------------------------------------------------------*/
/*
 * UDP handler.
 */
static void udp_handler(process_event_t ev, process_data_t data)
{   
    snmp_packets++;
    u8t response[MAX_BUF_SIZE];
    u16t resp_len;
    #if CHECK_STACK_SIZE
    memset(response, 0, sizeof(response));
    #endif

    #if DEBUG && CONTIKI_TARGET_AVR_RAVEN
    u8t request[MAX_BUF_SIZE];
    u16t req_len;
    #endif /* DEBUG && CONTIKI_TARGET_AVR_RAVEN */
    if (ev == tcpip_event && uip_newdata()) {
        #if INFO
            uip_ipaddr_t ripaddr;
            u16_t rport;
            uip_ipaddr_copy(&ripaddr, &UDP_IP_BUF->srcipaddr);
            rport = UDP_IP_BUF->srcport;
        #else
            uip_ipaddr_copy(&udpconn->ripaddr, &UDP_IP_BUF->srcipaddr);
            udpconn->rport = UDP_IP_BUF->srcport;
        #endif

        #if DEBUG && CONTIKI_TARGET_AVR_RAVEN
        req_len = uip_datalen();
        memcpy(request, uip_appdata, req_len);
        if (dispatch(request, &req_len, response, resp_len, MAX_BUF_SIZE) != ERR_NO_ERROR) {
            udpconn->rport = 0;
            memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
            return;
        }
        #else

        if (dispatch((u8_t*)uip_appdata, uip_datalen(), response, &resp_len, MAX_BUF_SIZE) != ERR_NO_ERROR) {
            udpconn->rport = 0;
            memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
            return;
        }

        #endif /* DEBUG && CONTIKI_TARGET_AVR_RAVEN */

        #if CHECK_STACK_SIZE
        u32t *p = marker - 1;
        u16t i = 0;
        while (*p != 0xAAAAAAAA || *(p - 1) != 0xAAAAAAAA || *(p - 2) != 0xAAAAAAAA) {
            i+=4;
            p--;
        }
        if (i > max) {
            max = i;
        }
        snmp_info(" %d", max);
        #endif


        #if INFO
            uip_ipaddr_copy(&udpconn->ripaddr, &ripaddr);
            udpconn->rport = rport;
        #endif

        uip_udp_packet_send(udpconn, response, resp_len);
        
        memset(&udpconn->ripaddr, 0, sizeof(udpconn->ripaddr));
        udpconn->rport = 0;
    }
}
/*-----------------------------------------------------------------------------------*/

#include "md5.h"

/*-----------------------------------------------------------------------------------*/
/*
 *  Entry point of the SNMP server.
 */
PROCESS_THREAD(snmpd_process, ev, data) {
	PROCESS_BEGIN();

	snmp_packets = 0;

        #ifndef CONTIKI_TARGET_AVR_RAVEN
        systemStartTime = clock_time();
        #endif

        #if CHECK_STACK_SIZE
        u16t i = 0;
        u32t pointer;
        u32t* p = &pointer;
        for (i = 0; i < 1000; i++) {
            *p = 0xAAAAAAAA;
            p--;
        }
        marker = &pointer;
        #endif

	udpconn = udp_new(NULL, UIP_HTONS(0), NULL);
	udp_bind(udpconn, UIP_HTONS(LISTEN_PORT));

        /* init MIB */
        if (mib_init() != -1) {
            
            while(1) {
                PROCESS_YIELD();
                udp_handler(ev, data);
            }
        } else {
            snmp_log("error occurs while initializing the MIB\n");
        }
	PROCESS_END();
}
