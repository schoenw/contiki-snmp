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

#include "net/uip.h"
#include "net/uip-mcast6.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINT6ADDR(addr) PRINTF(" %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x ", ((u8_t *)addr)[0], ((u8_t *)addr)[1], ((u8_t *)addr)[2], ((u8_t *)addr)[3], ((u8_t *)addr)[4], ((u8_t *)addr)[5], ((u8_t *)addr)[6], ((u8_t *)addr)[7], ((u8_t *)addr)[8], ((u8_t *)addr)[9], ((u8_t *)addr)[10], ((u8_t *)addr)[11], ((u8_t *)addr)[12], ((u8_t *)addr)[13], ((u8_t *)addr)[14], ((u8_t *)addr)[15])
#endif

static my_maddr_list_t *list = NULL;

int uip_maddr_add(uip_ipaddr_t addr){
  if(list == NULL) {
    list = (my_maddr_list_t *) malloc(sizeof(my_maddr_list_t));
    
    uip_ipaddr_copy(&list->mipaddr, &addr);
    list->next = NULL;
    list->prev = NULL;
  }
  else {
    my_maddr_list_t *current;
    for(current = list; current->next != NULL; current = current->next);
    
    current->next = (my_maddr_list_t *) malloc(sizeof(my_maddr_list_t));

    uip_ipaddr_copy(&current->next->mipaddr, &addr);
    current->next->next = NULL;
    current->next->prev = current;    
  }
  return 0;
}

my_maddr_list_t* uip_my_maddr(uip_ipaddr_t addr){
  my_maddr_list_t *current;
  for(current = list; current != NULL; current = current->next){
    if(uip_ipaddr_cmp(&current->mipaddr, &addr)){
      return current;
    }      
  }
  return NULL;
}

int uip_maddr_rm(uip_ipaddr_t addr){
  my_maddr_list_t *temp = uip_my_maddr(addr);
  if(temp != NULL) {
    if(temp->next == NULL && temp->prev == NULL){ //only element
      free(temp);

      list = NULL;      
      return 0;
    }
    else if(temp->prev == NULL){  //first element
      list = temp->next;
      list->prev = NULL;

      free(temp);
      return 0;
    }
    else if (temp->next == NULL){ //last element
      temp->prev->next = NULL;
      free(temp);

      return 0;
    }
    else {
      temp->prev->next = temp->next;
      temp->next->prev = temp->prev;

      free(temp);
    }
  }
  return 1;
}

/*
 * Functions defined in uip-mcast6.h follow.
 */

struct uip_udp_conn* udp_mcast_new(const uip_ipaddr_t *ripaddr, u16_t rport){
  struct uip_udp_conn *conn;

  conn = udp_new(ripaddr, UIP_HTONS(0), NULL);
  udp_bind(conn, rport);

  uip_maddr_add(*ripaddr);

  return conn;
}

int udp_mcast_close(struct uip_udp_conn *conn){
  uip_maddr_rm(conn->ripaddr);

  conn->lport = 0;
  memset(&conn->ripaddr, 0, sizeof(uip_ipaddr_t));

  return 0;
}

int uip_maddr_exists(uip_ipaddr_t addr){
  my_maddr_list_t *temp = uip_my_maddr(addr);

  if(temp != NULL)
    return 1;

  return 0;
}

#ifdef DEBUG
int my_maddr_all(){
  my_maddr_list_t *current;
  for(current = list; current != NULL; current = current->next){
    PRINT6ADDR(&current->mipaddr);
    PRINTF("\n");
  }
  PRINTF("\n");

  return 0;
}
#endif

