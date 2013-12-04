/*
 * Copyright (c) 2006, Swedish Institute of Computer Science.
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
 * $Id: webserver6.c,v 1.1 2008/10/14 22:04:16 c_oflynn Exp $
 */

#include "webserver-nogui.h"
#include "snmpd.h"
#include "raven-lcd.h"
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "sysman.h"
#include "net/uip-mcast6.h"
#include "mac.h"
#include <stdio.h>

PROCESS(lcd_process, "LCD Updater");

/*---------------------------------------------------------------------------*/
AUTOSTART_PROCESSES(&webserver_nogui_process, &snmpd_process, &lcd_process);
/*---------------------------------------------------------------------------*/

PROCESS_THREAD(lcd_process, ev, data) {
  static struct etimer et;
  char text[50];

  PROCESS_BEGIN();

  etimer_set(&et, CLOCK_SECOND * 10);
  raven_lcd_show_text("SNMP Test Mote");
  PROCESS_WAIT_UNTIL(etimer_expired(&et));

  getTemperature("C");

  etimer_set(&et, CLOCK_SECOND * 1);
  while(1){
    PROCESS_YIELD();
    if(etimer_expired(&et)){
      sprintf(text, "S %d", snmp_packets);
      raven_lcd_show_text(text);
      etimer_restart(&et);
    }
  }
  
  PROCESS_END();
}
