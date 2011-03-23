#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "syslog.h"

#include "mac.h"

#include <string.h>

#define SEND_INTERVAL		1 * CLOCK_SECOND

PROCESS(udp_client_process, "UDP client process");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static void
set_connection_address(uip_ipaddr_t *ipaddr)
{
  uip_ip6addr(ipaddr,0xaaaa,0,0,0,0,0,0,0x0001);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer et;
  static uip_ipaddr_t ipaddr;
  char buf[UIP_APPDATA_SIZE];

  PROCESS_BEGIN();
  PRINTF("UDP client process started\n");

  printf("UIP SIZE: %d\n", UIP_APPDATA_SIZE);

  set_connection_address(&ipaddr);
  etimer_set(&et, SEND_INTERVAL);
  
  while(1) {
    PROCESS_YIELD();
    if(etimer_expired(&et)) {    
      syslog_msg(buf, FAC_SYSTEM, SEV_INFO, PROCESS_CURRENT(), "All is well");

      //syslog_send(buf, NULL);
      syslog_send(buf, &ipaddr);

      etimer_restart(&et);
    }
  }
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
