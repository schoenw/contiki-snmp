/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "mdns.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#define DEBUG DEBUG_PRINT
#include "net/uip-debug.h"

#define SEND_INTERVAL		3 * CLOCK_SECOND
#define MAX_PAYLOAD_LEN		40
typedef struct {
  uint16_t Identification;

  union {
    struct {
      unsigned char Rcode  : 4;    
      unsigned char CD     : 1;
      unsigned char AD     : 1;
      unsigned char Z      : 1;
      unsigned char RA     : 1;

      unsigned char RD     : 1;
      unsigned char TC     : 1;
      unsigned char AA     : 1;    
      unsigned char Opcode : 4;
      unsigned char QR     : 1;      
    };
    uint16_t Flags;
  };
  
  uint16_t TotQuestions;
  uint16_t TotAnsRR;
  uint16_t TotAuthRR;
  uint16_t TotAddRR;
  
} mdns_header_t;

struct RRinfo{
  uint16_t RRtype;
  uint16_t RRclass;
  uint32_t RRttl;
  uint16_t RDataLen;
};

static struct uip_udp_conn *client_conn;
/*---------------------------------------------------------------------------*/
PROCESS(mdns_querier_process, "mdnsQuerier process");
/*---------------------------------------------------------------------------*/
static char *buf;
void tcpip_handler(void){
  printf("\n***** Packet Received *****\n");
}
/*---------------------------------------------------------------------------*/
static void
timeout_handler(void)
{
  //DNS header
  mdns_header_t header;

  header.QR = 0;
  header.Opcode = 0;
  header.AA = 0;
  header.TC = 0;
  header.RD = 0;

  header.RA = 0;
  header.Z = 0;
  header.AD = 0;
  header.CD = 0;
  header.Rcode = 0;
  
  header.Identification = UIP_HTONS(0);
  header.Flags = UIP_HTONS(header.Flags);
  header.TotQuestions = UIP_HTONS(1);
  header.TotAnsRR = UIP_HTONS(0);
  header.TotAuthRR = UIP_HTONS(0);
  header.TotAddRR = UIP_HTONS(0);


  char *qname;
  int qSize;
  qname = (char *) malloc(70 * sizeof(char));
  sprintf(qname, "%c_syslog%c_udp%clocal%c", 7, 4, 5, 0);

  uint16_t Qtype = uip_htons(12);
  uint16_t Qclass = uip_htons(1);
  qSize = ((sizeof(char) * strlen(qname)) + sizeof(char)) + sizeof(uint16_t)+sizeof(uint16_t);


  int packetSize;

  packetSize = sizeof(header)+qSize;
  
  //printf("packet size %d\n", packetSize);



  buf = (void *) malloc(packetSize);

  memcpy(buf, &header, sizeof(header));

  memcpy(buf+sizeof(header) , qname, strlen(qname)+sizeof(char));
  memcpy(buf+sizeof(header)+strlen(qname)+sizeof(char), &Qtype, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+strlen(qname)+sizeof(char)+sizeof(uint16_t), &Qclass, sizeof(uint16_t));

  client_conn->rport = UIP_HTONS(5353);
  uip_udp_packet_send(client_conn, buf, packetSize);
  //printf("packet sent\n");
  client_conn->rport = UIP_HTONS(0);

  free(buf);
  free(qname);
}
/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Client IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
    }
  }
}
/*---------------------------------------------------------------------------*/
#if UIP_CONF_ROUTER
static void
set_global_address(void)
{
  uip_ipaddr_t ipaddr;

  uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);
}
#endif /* UIP_CONF_ROUTER */
/*---------------------------------------------------------------------------*/
static void
set_connection_address(uip_ipaddr_t *ipaddr)
{
  uip_ip6addr(ipaddr,0xff02,0,0,0,0,0,0,0x00FB);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(mdns_querier_process, ev, data)
{
  static struct etimer et;
  uip_ipaddr_t ipaddr;

  PROCESS_BEGIN();
  printf("mdnsQuerier process started\n");

#if UIP_CONF_ROUTER
  set_global_address();
#endif

  print_local_addresses();

  set_connection_address(&ipaddr);

  /* new connection with remote host */
  client_conn = udp_new(&ipaddr, UIP_HTONS(0), NULL);
  udp_bind(client_conn, UIP_HTONS(5353));

  PRINTF("Created a connection with the server ");
  PRINT6ADDR(&client_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n",
	UIP_HTONS(client_conn->lport), UIP_HTONS(client_conn->rport));

  etimer_set(&et, SEND_INTERVAL);
  while(1) {
    PROCESS_YIELD();
    if(etimer_expired(&et)) {
      timeout_handler();
      responder_timeout_handler(client_conn);
      etimer_restart(&et);
    } else if(ev == tcpip_event) {
      processor_tcpip_handler();
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
