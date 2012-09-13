/*
 * Copyright (c) 2001-2011, Anuj Sehgal.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the uIP TCP/IP stack.
 *
 *
 */

#ifndef __UIP_MCAST_H__
#define __UIP_MCAST_H__

#include "net/uip.h"

typedef struct my_maddr_list_t {
  uip_ipaddr_t mipaddr;
  struct my_maddr_list_t *next;
  struct my_maddr_list_t *prev;
} my_maddr_list_t;


/*---------------------------------------------------------------------------*/
/* First, the functions that should be called from the system to subscribe
 * to multicast groups.
 */
/**
 * Set the multicast IP addresses of this host and create a UDP connection
 * to that IP address for sending and receiving data.
 *
 * Example:

 my_conn = udp_mcast_new(&ipaddr, UIP_HTONS(port));
 
 */
struct uip_udp_conn* udp_mcast_new(const uip_ipaddr_t *ripaddr, u16_t rport);

/**
 * Check if this multicast IP address is subscribed to.
 *
 * Example:

 uip_maddr_exists(addr);

 */
int uip_maddr_exists(uip_ipaddr_t addr);

/**
 * Remove the multicast IP address subscription.
 *
 * Example:
 
 uip_mcast_close(&my_conn);

 */
int udp_mcast_close(struct uip_udp_conn *conn);

uint32_t mcast_packets;

#ifdef DEBUG
int my_maddr_all();
#endif

#endif /* __UIP_MCAST_H__ */
