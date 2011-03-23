/* -----------------------------------------------------------------------------
 * SNMP implementation for Contiki
 *
 * Copyright (C) 2010 Siarhei Kuryla
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "logging.h"
#include "ber.h"

#if CONTIKI_TARGET_AVR_RAVEN && ENABLE_PROGMEM
#include <avr/pgmspace.h>
#endif

/*---------------------------------------------------------*/
/*
 *  OID functions.
 */
ptr_t* oid_create()
{
    ptr_t* new_el_ptr = malloc(sizeof(ptr_t));
    if (!new_el_ptr) return 0;
    new_el_ptr->len = 0;
    return new_el_ptr;
}

void oid_free(ptr_t* ptr)
{
    if (ptr) {
        free(ptr);
    }
}

u16t oid_length(ptr_t* oid)
{
    #if CONTIKI_TARGET_AVR_RAVEN && ENABLE_PROGMEM
        return pgm_read_word(&oid->len);
    #else
        return oid->len;
    #endif
}

int oid_cmp(ptr_t* req_oid, ptr_t*  progmem_oid)
{
    #if CONTIKI_TARGET_AVR_RAVEN && ENABLE_PROGMEM
        u16t len = oid_length(progmem_oid);
        return memcmp_P(req_oid->ptr, (PGM_P)pgm_read_word(&progmem_oid->ptr), min(req_oid->len, len));
    #else
        return memcmp(req_oid->ptr, progmem_oid->ptr, min(req_oid->len, progmem_oid->len));
    #endif
}

int oid_cmpn(ptr_t* req_oid, ptr_t*  progmem_oid, u8t len)
{
    #if CONTIKI_TARGET_AVR_RAVEN && ENABLE_PROGMEM
        return memcmp_P(req_oid->ptr, (PGM_P)pgm_read_word(&progmem_oid->ptr), min(req_oid->len, len));
    #else
        return memcmp(req_oid->ptr, progmem_oid->ptr, min(req_oid->len, len));
    #endif
}


s8t oid_copy(ptr_t* dest, ptr_t* src, u8t malloc_len)
{
    #if CONTIKI_TARGET_AVR_RAVEN && ENABLE_PROGMEM
        dest->len = oid_length(src);
    #else
        dest->len = src->len;
    #endif

    if (!malloc_len) {
        dest->ptr = malloc(dest->len);
    } else {
        dest->ptr = malloc(malloc_len);
    }
    CHECK_PTR(dest->ptr);
    
    #if CONTIKI_TARGET_AVR_RAVEN && ENABLE_PROGMEM
        memcpy_P(dest->ptr, (PGM_P)pgm_read_word(&src->ptr), dest->len);
    #else
        memcpy(dest->ptr, src->ptr, dest->len);
    #endif
    return 0;
}
/*---------------------------------------------------------*/
/*
 *  MIB object list functions.
 */
mib_object_list_t* mib_object_list_append(mib_object_list_t* ptr, mib_object_t* value)
{
    mib_object_list_t* new_el_ptr = malloc(sizeof(mib_object_list_t));
    if (!new_el_ptr) return 0;

    new_el_ptr->next_ptr = 0;
    new_el_ptr->value = value;
    if (ptr) {
        ptr->next_ptr = new_el_ptr;
    }
    return new_el_ptr;
}

void mib_object_list_free(mib_object_list_t* ptr)
{
    while (ptr) {
        mib_object_list_t* next = ptr->next_ptr;
        free(ptr);
        ptr = next;
    }
}

/*---------------------------------------------------------*/
/*
 *  Variable binding list functions.
 */
varbind_list_item_t* varbind_list_append(varbind_list_item_t* ptr)
{
    varbind_list_item_t* new_el_ptr = malloc(sizeof(varbind_list_item_t));
    if (!new_el_ptr) return 0;
    new_el_ptr->next_ptr = 0;
    if (ptr) {
        ptr->next_ptr = new_el_ptr;
    }
    return new_el_ptr;
}

/*---------------------------------------------------------*/
/*
 *  Variable binding
 */
varbind_t* varbind_create()
{
    varbind_t* new_el_ptr = malloc(sizeof(varbind_t));
    if (!new_el_ptr) return 0;
    return new_el_ptr;
}

/*---------------------------------------------------------*/
/*
 *  MIB object list functions.
 */
mib_object_t* mib_object_create()
{
    mib_object_t* new_el_ptr = malloc(sizeof(mib_object_t));
    if (!new_el_ptr) return 0;
    new_el_ptr->next_ptr = 0;
    return new_el_ptr;
}


void free_varbinds(pdu_t* pdu)
{
    varbind_list_item_t* ptr = pdu->varbind_first_ptr;
    u8t i = 0;
    while (ptr) {
        i++;
        if (pdu->response_type != BER_TYPE_SNMP_REPORT) {
            #if ENABLE_MIB_TABLE || ENABLE_PROGMEM
            /* release memory allocated while processing the request */
            if (pdu->request_type == BER_TYPE_SNMP_GETNEXT && pdu->response_type == BER_TYPE_SNMP_RESPONSE) {
                if ((!pdu->error_status || (pdu->error_status && i < pdu->error_index)) &&
                        ptr->varbind.value_type != BER_TYPE_END_OF_MIB) {
                    free(ptr->varbind.oid_ptr->ptr);
                }
            }
            #endif
            oid_free(ptr->varbind.oid_ptr);
        }
        varbind_list_item_t* next_ptr = ptr->next_ptr;
        free(ptr);
        ptr = next_ptr;
    }
}
/*-----------------------------------------------------------------------------------*/
/*
 * Free the memory from the heap used for storing the message content.
 */
void free_message(message_t* message)
{
    free_varbinds(&message->pdu);
    /* free memory for string values */
    free(message);
}

void print_array_as_hex (const u8t *digest, u8t len)
{
    int i;
    for(i = 0; i < len; i++) {
        snmp_log("%02x", digest[i]);
    }
    snmp_log("\n");
}

void convert_2_octets(u8t* dest, u32t value)
{
    dest[0] = (value >> 24) & 0xFF;
    dest[1] = (value >> 16) & 0xFF;
    dest[2] = (value >> 8) & 0xFF;
    dest[3] = value & 0x000000FF;
}