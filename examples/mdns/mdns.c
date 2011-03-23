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

#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "net/uip-mcast6.h"

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])
#define UIP_UDP_BUF   ((struct uip_udp_hdr *)&uip_buf[UIP_LLIPH_LEN])

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

static struct uip_udp_conn *client_conn;
/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  char *str;

  printf("Multicast Message Received from: ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  printf(" (%d)", UIP_HTONS(UIP_UDP_BUF->srcport));
  printf("\n");

  if(uip_newdata()) {
    str = uip_appdata;
    str[uip_datalen()] = '\0';
    //printf("Response from the server: '%s'\n", str);
  }
}
static char *buf;
/*---------------------------------------------------------------------------*/
static void
timeout_handler(void)
{
  //uip_ipaddr_t ipaddr;

  mdns_header_t header;
  //mdns_header_t header2;

  char *domainName;

  uint16_t RRtype=uip_htons(5);
  uint16_t RRclass=uip_htons(1);
  uint32_t RRttl=uip_ntohl(10);
  int packetSize;

  header.QR = 1;
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
  header.TotQuestions = UIP_HTONS(0);
  header.TotAnsRR = UIP_HTONS(1);
  header.TotAuthRR = UIP_HTONS(0);
  header.TotAddRR = UIP_HTONS(0);

  domainName = (char *) malloc(70 * sizeof(char));
  sprintf(domainName, "%canuj%clocal%c", 4, 5, 0);
  //printf("%s len:%d\n", domainName, strlen(domainName));
  uint16_t RDataLen = uip_htons(strlen(domainName)+sizeof(char));

  //printf("(msg size %d, flags %x) Client sending to: ", sizeof(header), header.Flags+strlen(domainName)+sizeof(char));
  //PRINT6ADDR(&client_conn->ripaddr);
  //printf("Remote Port %d\n", client_conn->rport);
  //printf("\n\n");

  packetSize = sizeof(header) + ((sizeof(char) * strlen(domainName)) + sizeof(char)) +
               sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint16_t)+
               (sizeof(char) * strlen(domainName)) + sizeof(char);
  
  buf = (void *) malloc(packetSize);

  memcpy(buf, &header, sizeof(header));
  memcpy(buf+sizeof(header), domainName, strlen(domainName)+sizeof(char));
  memcpy(buf+sizeof(header)+strlen(domainName)+sizeof(char), &RRtype, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+strlen(domainName)+sizeof(char)+sizeof(uint16_t), &RRclass, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+strlen(domainName)+sizeof(char)+(2*sizeof(uint16_t)), &RRttl, sizeof(uint32_t));
  memcpy(buf+sizeof(header)+strlen(domainName)+sizeof(char)+(2*sizeof(uint16_t))+sizeof(uint32_t), &RDataLen, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+strlen(domainName)+sizeof(char)+(3*sizeof(uint16_t))+sizeof(uint32_t), domainName, strlen(domainName)+sizeof(char));

  memcpy(&header, buf, sizeof(header));
  //printf("(flags %x) After memcpy()\n", header.Flags);

  client_conn->rport = UIP_HTONS(5353);

  uip_udp_packet_send(client_conn, buf, packetSize);

  client_conn->rport = 0;

  free(domainName);
  free(buf);
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
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer et;
  uip_ipaddr_t ipaddrMcast;

  PROCESS_BEGIN();
  PRINTF("UDP client process started\n");

#if UIP_CONF_ROUTER
  set_global_address();
#endif


  uip_ip6addr(&ipaddrMcast,0xff02,0,0,0,0,0,0,0x00fb);

  client_conn = udp_mcast_new(&ipaddrMcast, UIP_HTONS(5353));

  udp_mcast_close(client_conn);

  client_conn = udp_mcast_new(&ipaddrMcast, UIP_HTONS(5353));

  PRINTF("Created a connection with the server ");
  PRINT6ADDR(&client_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n",
	UIP_HTONS(client_conn->lport), UIP_HTONS(client_conn->rport));

  etimer_set(&et, SEND_INTERVAL);
  while(1) {
    PROCESS_YIELD();
    if(etimer_expired(&et)) {
      timeout_handler();
      etimer_restart(&et);
    } else if(ev == tcpip_event) {
      tcpip_handler();
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
