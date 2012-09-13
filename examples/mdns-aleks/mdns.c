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

#define SEND_INTERVAL		10 * CLOCK_SECOND
#define PTR			12
#define TXT			16
#define AAAA			28
#define SRV			33


void decompress(char *label, uint8_t location, uint8_t *data){
   uint8_t *ptr;
   ptr = data + location;
   while(1){
	if(*ptr==192){ptr++; decompress(label, *ptr, data); break;} //recursively call the function with the new location
	else if(*ptr==0) break;  
   	strncpy(label, (char *) ptr + 1, *ptr);
	label+= *ptr;
	*label = '.';
	label++;
	ptr += *ptr +1;
   }   
}
char *composeLabel(uint8_t *ptr, uint8_t *data){//don't forget to free later
	char *label, *lblptr;
	label = lblptr = (char *) malloc(256);
	memset(lblptr, 0, 256);
	while(1){
	   if(*ptr == 192) {ptr++; decompress(label, *ptr, data); break; }
           else if(*ptr == 0) {break;}
	   strncpy(label, (char *) ptr+1, *ptr);
	   label+=*ptr;
	   *label = '.';
	   label ++;
	   ptr +=  *ptr+1;
	}
	//printf("Query for: %d %s\n",strlen(lblptr),lblptr);
	return lblptr;
}

int labelLength(uint8_t *label){
	int length=0;
	while( (*label != 0) && (*label != 192)){
		length++;
		label++;
	}
	if(*label==192) length+=2;
	else if(*label==0)	length++;
	return length;
	
}

uint16_t combineTwo(uint8_t *ptr){
	uint16_t two;
	two=(*ptr)*256;
	ptr++;
	two+=*ptr;
	return two;

}
uint16_t extractClass(uint8_t *ptr){
	uint16_t cls;
	cls=(*ptr)*256;
	ptr++;
	cls+=*ptr;
	cls=(cls & 32767); //remove most significant bit
	return cls;

}
uint16_t extractFirst(uint8_t *ptr){
	uint16_t um;
	um=(*ptr)*256;
	ptr++;
	um+=*ptr;
	um=(um & 32768);
	return um>>15;

}

uint32_t extractTTL(uint8_t *ptr){
	uint32_t ttl=0,tmp;
	tmp=(*ptr); tmp=(tmp<<24); ttl+=tmp; //1st byte
	ptr++;
	tmp=(*ptr); tmp=(tmp<<16); ttl+=tmp; //2nd byte
	ptr++;	
	tmp=(*ptr); tmp=(tmp<<8); ttl+=tmp; //3rd byte
	ptr++;
	ttl+=(*ptr); //4th
	return ttl;		
}
static struct uip_udp_conn *client_conn;
/*---------------------------------------------------------------------------*/
PROCESS(udp_mcast_process, "UDP client process");
AUTOSTART_PROCESSES(&udp_mcast_process);
/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
  uint8_t *data, opcode, aa, tc, rd, ra, z, ad, cd, rcode, qr, extract_last4=15, extract_last1=1 ; 
  uint16_t identification, questions, answerRRs, authorityRRs, additionalRRs, totalRRs;

  printf("Multicast Message Received from: ");
  PRINT6ADDR(&UIP_IP_BUF->srcipaddr);
  printf(" (%d)", UIP_HTONS(UIP_UDP_BUF->srcport));
  printf("\n");

  if(uip_newdata()) {
    data = uip_appdata;
    //str[uip_datalen()] = '\0';
    identification=(data[0]*256+data[1]);
    qr=(data[2]>>7);				//0 for query 1 for response
    opcode=((data[2]>>3) & extract_last4);
    aa=((data[2]>>2) & extract_last1);
    tc=((data[2]>>1) & extract_last1);
    rd=(data[2] & extract_last1);
    ra=((data[3]>>7) & extract_last1);
    z=((data[3]>>6) & extract_last1);
    ad=((data[3]>>5) & extract_last1);
    cd=((data[3]>>4) & extract_last1);
    rcode=(data[3] & extract_last4);
    questions=(data[4]*256+data[5]);
    answerRRs=(data[6]*256+data[7]);
    authorityRRs=(data[8]*256+data[9]);
    additionalRRs=(data[10]*256+data[11]);
    totalRRs = answerRRs + authorityRRs + additionalRRs;

    printf("Identification: '%d'\n", identification);
    printf("QR:'%u' (0=>query, 1=>response)\n", qr);    
    printf("Opcode:'%u'\n", opcode);
    printf("AA:'%u'\n", aa);
    printf("TC:'%u'\n", tc);
    printf("RD:'%u'\n", rd);
    printf("RA:'%u'\n", ra);
    printf("Z:'%u'\n", z);
    printf("AD:'%u'\n", ad);
    printf("CD:'%u'\n", cd);
    printf("Rcode:'%u'\n", rcode);
    printf("Total questions: '%d'\n", questions);
    printf("Total answer RRs: '%d'\n", answerRRs);
    printf("Total authority RRs: '%d'\n", authorityRRs);
    printf("Total aditional RRs: '%d'\n", additionalRRs);
    printf("-------------------                           -------------------------\n");  

  
    uint8_t *ptr, *rrDataPtr;
    ptr = data+12;
  
    if((qr == 0) || (qr==1)){
        printf("\nQUESTIONS:\n");
	char *label;
	while(questions>0){
		//later create structure and fill in data from queries
		label = composeLabel(ptr, data);
		printf("%s\n",label);
		free(label);
		ptr+= labelLength(ptr); //now points to first byte from Type
		printf("Type: %d  ",combineTwo(ptr));
		ptr+=2;
		printf("Class: %d  ",extractClass(ptr));
		printf("QU or QM: %d\n\n", extractFirst(ptr));
		ptr+=2;
		questions--;
	}
   	printf("\nANSWERS:\n\n");
    	char *name, *dName, *target, *txtData;
	int type, cls, flush, rDataLength, i=1;
	uint32_t ttl;
	while(totalRRs>0){
		//later try to create generic structure and fill in data from answers
		name = composeLabel(ptr,data);
		ptr+= labelLength(ptr);
		type=combineTwo(ptr);
		ptr+=2;
		cls=extractClass(ptr);
		flush=extractFirst(ptr);
		ptr+=2;
		ttl=extractTTL(ptr);
		ptr+=4;
		rDataLength=combineTwo(ptr);
		printf("Name: %s\n", name);
		free(name);
		printf("Type: %d  ", type);
		printf("Class: %d  ", cls);
		printf("Flush: %d  ", flush);
		printf("TTL: %lu seconds \n",ttl);
		printf("Data Length: %d \n", rDataLength);
		ptr+=2;//now points at the start of the data
		rrDataPtr=ptr; //to avoid errors

		switch(type){
			case PTR:
				dName = composeLabel(rrDataPtr,data);
				printf("Domain name: %s\n\n", dName);
				free(dName);
				break;
			case AAAA:
				printf("AAAA: ");
				while(i<17){
					printf("%x",*rrDataPtr);
					rrDataPtr++;
					i++;
					if((i%2)==0) printf(":");
				}
				printf("\n");
				break;
			case SRV:
				printf("Priority: %d \n", combineTwo(rrDataPtr));
				rrDataPtr+=2;
				printf("Weight: %d \n", combineTwo(rrDataPtr));
				rrDataPtr+=2;
				printf("Port: %d \n", combineTwo(rrDataPtr));
				rrDataPtr+=2;
				target = composeLabel(rrDataPtr,data);
				printf("Target: %s \n\n", target);
				free(target);
				break;
			case TXT:
				txtData = (char*) malloc (rDataLength*sizeof(char));
				strncpy(txtData, (char *) rrDataPtr, rDataLength);
				printf("TXT DATA: %s\n", txtData);
				free(txtData);
				break;
			default:
				printf("Type of no interest: %d\n\n", type);
				break;
		}
		ptr+=rDataLength; //now points to the first byte from the next RR
		totalRRs--;
		// next step would be to check if Name for the PTR == the service type we are looking
		// if there exists SRV and TXT with the same instance name as in the PTR
		// find the AAAA RR for that service  

	}
    }
  }
  printf("-----------------------------------------------------------------------\n");
}

/*---------------------------------------------------------------------------*/
static void
timeout_handler(void)
{
  client_conn->rport = UIP_HTONS(5353);
  //uip_udp_packet_send(client_conn, "Hello! Multicast\n", strlen("Hello! Multicast\n"));
  client_conn->rport = 5353;
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_mcast_process, ev, data)
{
  static struct etimer et;
  uip_ipaddr_t ipaddrMcast;

  PROCESS_BEGIN();
  PRINTF("UDP multicast process started\n");

  uip_ip6addr(&ipaddrMcast,0xff02,0,0,0,0,0,0,0x00fb);
  client_conn = udp_mcast_new(&ipaddrMcast, UIP_HTONS(5353));

  PRINTF("Created a connection with the server ");
  PRINT6ADDR(&client_conn->ripaddr);
  PRINTF(" local/remote port %u/%u\n",
	UIP_HTONS(client_conn->lport), UIP_HTONS(client_conn->rport));

  etimer_set(&et, SEND_INTERVAL/2);
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
