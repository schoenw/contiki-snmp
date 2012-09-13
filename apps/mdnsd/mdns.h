#ifndef __MDNSD_H__
#define __MDNSD_H__

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/uip.h"

/*
#include "net/uipopt.h"
#include "net/uip_arp.h"
#include "net/uip_arch.h"
#include "net/uip-neighbor.h"
*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#define DEBUG DEBUG_PRINT
#include "net/uip-debug.h"


//PROCESS_NAME(mdns_responder_process);
PROCESS_NAME(mdns_querier_process);
PROCESS_NAME(mdns_processor_process);

typedef struct {
  char *srv;
  char *host;
  uip_ipaddr_t aaaa;
  struct mdns_records_list_t *next;
  struct mdns_records_list_t *prev;
} mdns_records_list_t;

uip_ipaddr_t getAAAArecord();

int mdns_query(char*);


void responder_timeout_handler(struct uip_udp_conn *client_conn);
void processor_tcpip_handler();

#endif /* __NTPD_H__ */
