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
PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  char *str;

  if(uip_newdata()) {
    str = uip_appdata;
    str[uip_datalen()] = '\0';
    printf("Response from the server: '%s'\n", str);
  }
}
static char *buf;

/*---------------------------------------------------------------------------*/
static void
timeout_handler(void)
{
  
  //DNS header
  mdns_header_t header;

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
  header.TotAnsRR = UIP_HTONS(2);
  header.TotAuthRR = UIP_HTONS(0);
  header.TotAddRR = UIP_HTONS(5);

  //PTR record for the type of service

  char *name1;
  char *rdata1;
  int rr1Size;

  name1 = (char *) malloc(70 * sizeof(char));
  sprintf(name1, "%c_services%c_dns-sd%c_udp%clocal%c", 9, 7, 4, 5, 0);

  rdata1 = (char *) malloc(70 * sizeof(char));
  sprintf(rdata1, "%c_daap%c_tcp%clocal%c", 5, 4, 5, 0);

  uint16_t RRtype1 = uip_htons(12);
  uint16_t RRclass1 = uip_htons(1);
  uint32_t RRttl1 = uip_ntohl(100);

  uint16_t RDataLen1 = uip_htons(strlen(rdata1)+sizeof(char));

  rr1Size = ((sizeof(char) * strlen(name1)) + sizeof(char)) + sizeof(uint16_t) + sizeof(uint16_t) +
	    sizeof(uint32_t) + sizeof(uint16_t) + (sizeof(char) * strlen(rdata1)) + sizeof(char);

  //PTR record for the instance of the type of service
  char *name2;
  char *rdata2;
  int rr2Size;

  name2 = (char *) malloc(70* sizeof(char));
  sprintf(name2, "%c_daap%c_tcp%clocal%c", 5, 4, 5, 0);

  rdata2 = (char *) malloc(70* sizeof(char));
  sprintf(rdata2, "%cHello World%c_daap%c_tcp%clocal%c", 11, 5, 4, 5, 0);
  
  uint16_t RRtype2 = uip_htons(12);
  uint16_t RRclass2 = uip_htons(1);
  uint32_t RRttl2 = uip_ntohl(100);

  uint16_t RDataLen2 = uip_htons(strlen(rdata2)+sizeof(char));

  rr2Size = ((sizeof(char) * strlen(name2)) + sizeof(char)) + sizeof(uint16_t) + sizeof(uint16_t) +
	    sizeof(uint32_t) + sizeof(uint16_t) + (sizeof(char) * strlen(rdata2)) + sizeof(char);

  //SRV record for the instance above
  char *name3;
  char *target;
  int rr3Size;

  name3 = (char *) malloc(70* sizeof(char));
  sprintf(name3, "%cHello World%c_daap%c_tcp%clocal%c", 11, 5, 4, 5, 0);
  
  target = (char *) malloc(70* sizeof(char));
  sprintf(target, "%cmote%clocal%c",4, 5, 0);
  
  uint16_t RRtype3 = uip_htons(33);
  uint16_t RRclass3 = uip_htons(32769);
  uint32_t RRttl3 = uip_ntohl(100);
  uint16_t priority3 = uip_htons(0);
  uint16_t weight3 = uip_htons(0);
  uint16_t port3 = uip_htons(8080);
 
  uint16_t RDataLen3 = uip_htons(strlen(target)+sizeof(char)+3*sizeof(uint16_t));
  
  rr3Size = ((sizeof(char) * strlen(name3)) + sizeof(char)) + sizeof(uint16_t) + sizeof(uint16_t) +
	    sizeof(uint32_t) + 4*sizeof(uint16_t) + (sizeof(char) * strlen(target)) + sizeof(char);

  //TXT record for the SRV above
  char *name4;
  char *txtData;
  int rr4Size;
  
  name4 = (char *) malloc(70* sizeof(char));
  sprintf(name4, "%cHello World%c_daap%c_tcp%clocal%c", 11, 5, 4, 5, 0);
  
  uint16_t RRtype4=uip_htons(16);
  uint16_t RRclass4=uip_htons(32769);
  uint32_t RRttl4=uip_ntohl(100);
  uint16_t RDataLen4 = uip_htons(16);
  txtData = (char *) malloc(70* sizeof(char));
  sprintf(txtData, "%cpath=/mywebsite",15);

  rr4Size = ((sizeof(char) * strlen(name4)) + sizeof(char)) +  sizeof(uint16_t) + sizeof(uint16_t) +
             sizeof(uint32_t) + sizeof(uint16_t) + 16;
 
  //AAAA record
  char *name5;
  int rr5Size;
 
  name5 = (char *) malloc(70* sizeof(char));
  sprintf(name5, "%cmote%clocal%c",4, 5, 0);

  uint16_t RRtype5=uip_htons(28);
  uint16_t RRclass5=uip_htons(32769);
  uint32_t RRttl5=uip_ntohl(100);
  
  uint16_t RDataLen5 = uip_htons(16*sizeof(char)+sizeof(char));
  
  rr5Size = ((sizeof(char) * strlen(name5)) + sizeof(char)) +  sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint16_t)+17;
  
  //NSEC for AAAA
  char *name6;
  int rr6Size;

  name6 = (char *) malloc(70* sizeof(char));
  sprintf(name6, "%cmote%clocal%c",4, 5, 0);

  uint16_t RRtype6=uip_htons(47);
  uint16_t RRclass6=uip_htons(32769);
  uint32_t RRttl6=uip_ntohl(1000); 

  uint16_t RDataLen6 = uip_htons(strlen(name6)+sizeof(char)+3*sizeof(uint16_t));
  
  uint16_t bsize1 = uip_htons(4);
  uint32_t typ1 = uip_ntohl(8);   
 
  rr6Size = ((sizeof(char) * strlen(name6)) + sizeof(char)) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint16_t)+
               (sizeof(char) * strlen(name6)) + sizeof(char)+ 3*sizeof(uint16_t);
   
  //NSEC for SRV+TX
  char *name7;
  int rr7Size;

  name7 = (char *) malloc(70* sizeof(char));
  sprintf(name7, "%cHello World%c_daap%c_tcp%clocal%c", 11, 5, 4, 5, 0);

  uint16_t RRtype7=uip_htons(47);
  uint16_t RRclass7=uip_htons(32769);
  uint32_t RRttl7=uip_ntohl(1000); 

  uint16_t RDataLen7 = uip_htons(strlen(name7)+2*sizeof(char)+3*sizeof(uint16_t));
  
  uint16_t bsize2 = uip_htons(1280);
  uint32_t typ2 = uip_ntohl(8388672);   
 
  rr7Size = ((sizeof(char) * strlen(name7)) + sizeof(char)) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint16_t)+
               (sizeof(char) * strlen(name7)) + 2*sizeof(char)+ sizeof(uint16_t) + sizeof(uint32_t);

  //combining

  int packetSize;

  packetSize = sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+rr5Size+rr6Size+rr7Size;
  
  printf("packet size %d\n", packetSize);

  buf = (void *) malloc(packetSize);

  memcpy(buf, &header, sizeof(header));

  memcpy(buf+sizeof(header) , name1, strlen(name1)+sizeof(char));
  memcpy(buf+sizeof(header)+strlen(name1)+sizeof(char), &RRtype1, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+strlen(name1)+sizeof(char)+sizeof(uint16_t), &RRclass1, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+strlen(name1)+sizeof(char)+(2*sizeof(uint16_t)), &RRttl1, sizeof(uint32_t));
  memcpy(buf+sizeof(header)+strlen(name1)+sizeof(char)+(2*sizeof(uint16_t))+sizeof(uint32_t), &RDataLen1, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+strlen(name1)+sizeof(char)+(3*sizeof(uint16_t))+sizeof(uint32_t), rdata1, strlen(rdata1)+sizeof(char));

  memcpy(buf+sizeof(header)+rr1Size , name2, strlen(name2)+sizeof(char));
  memcpy(buf+sizeof(header)+rr1Size+strlen(name2)+sizeof(char), &RRtype2, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+strlen(name2)+sizeof(char)+sizeof(uint16_t), &RRclass2, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+strlen(name2)+sizeof(char)+(2*sizeof(uint16_t)), &RRttl2, sizeof(uint32_t));
  memcpy(buf+sizeof(header)+rr1Size+strlen(name2)+sizeof(char)+(2*sizeof(uint16_t))+sizeof(uint32_t), &RDataLen2, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+strlen(name2)+sizeof(char)+(3*sizeof(uint16_t))+sizeof(uint32_t), rdata2, strlen(rdata2)+sizeof(char));

  memcpy(buf+sizeof(header)+rr1Size+rr2Size , name3, strlen(name3)+sizeof(char));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+strlen(name3)+sizeof(char), &RRtype3, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+strlen(name3)+sizeof(char)+sizeof(uint16_t), &RRclass3, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+strlen(name3)+sizeof(char)+(2*sizeof(uint16_t)), &RRttl3, sizeof(uint32_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+strlen(name3)+sizeof(char)+(2*sizeof(uint16_t))+sizeof(uint32_t), &RDataLen3, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+strlen(name3)+sizeof(char)+(3*sizeof(uint16_t))+sizeof(uint32_t), &priority3, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+strlen(name3)+sizeof(char)+(4*sizeof(uint16_t))+sizeof(uint32_t), &weight3, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+strlen(name3)+sizeof(char)+(5*sizeof(uint16_t))+sizeof(uint32_t), &port3, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+strlen(name3)+sizeof(char)+(6*sizeof(uint16_t))+sizeof(uint32_t), target, strlen(target)+sizeof(char));


  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size, name4, strlen(name4)+sizeof(char));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+strlen(name4)+sizeof(char), &RRtype4, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+strlen(name4)+sizeof(char)+sizeof(uint16_t), &RRclass4, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+strlen(name4)+sizeof(char)+(2*sizeof(uint16_t)), &RRttl4, sizeof(uint32_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+strlen(name4)+sizeof(char)+(2*sizeof(uint16_t))+sizeof(uint32_t), &RDataLen4, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+strlen(name4)+sizeof(char)+(3*sizeof(uint16_t))+sizeof(uint32_t), txtData, strlen(txtData));

  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size, name5, strlen(name5)+sizeof(char));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+strlen(name5)+sizeof(char), &RRtype5, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+strlen(name5)+sizeof(char)+sizeof(uint16_t), &RRclass5, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+strlen(name5)+sizeof(char)+(2*sizeof(uint16_t)), &RRttl5, sizeof(uint32_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+strlen(name5)+sizeof(char)+(2*sizeof(uint16_t))+sizeof(uint32_t), &RDataLen5, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+strlen(name5)+sizeof(char)+(3*sizeof(uint16_t))+sizeof(uint32_t), &uip_ds6_if.addr_list[1].ipaddr, 16);

  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+rr5Size, name6, strlen(name6)+sizeof(char));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+rr5Size+strlen(name6)+sizeof(char), &RRtype6, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+rr5Size+strlen(name6)+sizeof(char)+sizeof(uint16_t), &RRclass6, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+rr5Size+strlen(name6)+sizeof(char)+(2*sizeof(uint16_t)), &RRttl6, sizeof(uint32_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+rr5Size+strlen(name6)+sizeof(char)+(2*sizeof(uint16_t))+sizeof(uint32_t), &RDataLen6, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+rr5Size+strlen(name6)+sizeof(char)+(3*sizeof(uint16_t))+sizeof(uint32_t), name6, strlen(name6)+sizeof(char));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+rr5Size+strlen(name6)+2*sizeof(char)+(3*sizeof(uint16_t))+sizeof(uint32_t)+strlen(name6), &bsize1, sizeof(uint16_t));
 memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+rr5Size+strlen(name6)+2*sizeof(char)+(4*sizeof(uint16_t))+sizeof(uint32_t)+strlen(name6), &typ1, sizeof(uint32_t));  

  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+rr5Size+rr6Size, name7, strlen(name7)+sizeof(char));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+rr5Size+rr6Size+strlen(name7)+sizeof(char), &RRtype7, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+rr5Size+rr6Size+strlen(name7)+sizeof(char)+sizeof(uint16_t), &RRclass7, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+rr5Size+rr6Size+strlen(name7)+sizeof(char)+(2*sizeof(uint16_t)), &RRttl7, sizeof(uint32_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+rr5Size+rr6Size+strlen(name7)+sizeof(char)+(2*sizeof(uint16_t))+sizeof(uint32_t), &RDataLen7, sizeof(uint16_t));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+rr5Size+rr6Size+strlen(name7)+sizeof(char)+(3*sizeof(uint16_t))+sizeof(uint32_t), name7, strlen(name7)+2*sizeof(char));
  memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+rr5Size+rr6Size+strlen(name7)+3*sizeof(char)+(3*sizeof(uint16_t))+sizeof(uint32_t)+strlen(name7), &bsize2, sizeof(uint16_t));
 memcpy(buf+sizeof(header)+rr1Size+rr2Size+rr3Size+rr4Size+rr5Size+rr6Size+strlen(name7)+3*sizeof(char)+(4*sizeof(uint16_t))+sizeof(uint32_t)+strlen(name7), &typ2, sizeof(uint32_t));  

  uip_udp_packet_send(client_conn, buf, packetSize);
  printf("packet sent\n");
 
  free(buf);
  free(name1);
  free(rdata1);
  free(name2);
  free(rdata2);
  free(name3);
  free(target);
  free(name4);
  free(txtData);
  free(name5);
  free(name6);
  free(name7);
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
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer et;
  uip_ipaddr_t ipaddr;

  PROCESS_BEGIN();
  PRINTF("UDP client process started\n");

#if UIP_CONF_ROUTER
  set_global_address();
#endif

  print_local_addresses();

  set_connection_address(&ipaddr);

  /* new connection with remote host */
  client_conn = udp_new(&ipaddr, UIP_HTONS(5353), NULL);
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
      etimer_restart(&et);
    } else if(ev == tcpip_event) {
      tcpip_handler();
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
