/* -----------------------------------------------------------------------------
 * SNMP implementation for Contiki
 *
 * Copyright (C) 2010 Siarhei Kuryla <kurilo@gmail.com>
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
#include <string.h>

#include "cmd-responder.h"

#include "mib.h"
#include "ber.h"
#include "utils.h"
#include "logging.h"

#if ENABLE_SNMPv3

#endif

/*-----------------------------------------------------------------------------------*/
/*
 * Handle an SNMP GET request
 */
static s8t snmp_get(message_t* message)
{
    int i = 0;
    varbind_list_item_t* ptr = message->pdu.varbind_first_ptr;
    while (ptr) {
        i++;
        if (!mib_get(&ptr->varbind)) {
            if (message->version == SNMP_VERSION_1) {
                message->pdu.error_status = ERROR_STATUS_NO_SUCH_NAME;
                message->pdu.error_index = i;
                break;
            }
        }
        ptr = ptr->next_ptr;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Handle an SNMP GETNEXT request
 */
static s8t snmp_get_next(message_t* message)
{
    int i = 0;
    varbind_list_item_t* ptr = message->pdu.varbind_first_ptr;
    while (ptr) {
        i++;
        if (!mib_get_next(&ptr->varbind)) {
            if (message->version == SNMP_VERSION_1) {
                message->pdu.error_status = ERROR_STATUS_NO_SUCH_NAME;
                message->pdu.error_index = i;
                break;
            }
        }
        ptr = ptr->next_ptr;
    }
    return 0;
}


/*-----------------------------------------------------------------------------------*/
/*
 * Handle an SNMP SET request
 */
static s8t snmp_set(message_t* message)
{
    varbind_t tmp_var_bind;
    mib_object_list_t *var_index_ptr = 0, *cur_ptr = 0;

    varbind_list_item_t* ptr = message->pdu.varbind_first_ptr;
    u8t i = 0;
    mib_object_t* object;
    /* find mib objects and check their types */
    while (ptr) {
        i++;
        memcpy(&tmp_var_bind, &ptr->varbind, sizeof(varbind_t));
        if (!(object = mib_get(&tmp_var_bind))) {
            if (message->version == SNMP_VERSION_1) {
                message->pdu.error_status = ERROR_STATUS_NO_SUCH_NAME;
            } else {
                message->pdu.error_status = ERROR_STATUS_NOT_WRITABLE;
            }
            message->pdu.error_index = i;
            break;
        } else {
            if (!var_index_ptr) {
                cur_ptr = var_index_ptr = mib_object_list_append(0, object);
            } else {
                cur_ptr = mib_object_list_append(cur_ptr, object);
            }
        }
        if (tmp_var_bind.value_type != ptr->varbind.value_type) {
            snmp_log("bad value type %d %d\n", tmp_var_bind.value_type, ptr->varbind.value_type);
            if (message->version == SNMP_VERSION_1) {
                message->pdu.error_status = ERROR_STATUS_BAD_VALUE;
            } else {
                message->pdu.error_status = ERROR_STATUS_WRONG_TYPE;
            }
            message->pdu.error_index = i;
            break;
        }
        if (object->attrs & FLAG_ACCESS_READONLY) {
            snmp_log("read-only value %d %d\n", tmp_var_bind.value_type, ptr->varbind.value_type);
            if (message->version == SNMP_VERSION_1) {
                message->pdu.error_status = ERROR_STATUS_READONLY;
            } else {
                message->pdu.error_status = ERROR_STATUS_NOT_WRITABLE;
            }
            message->pdu.error_index = i;
            break;
        }
        ptr = ptr->next_ptr;
    }
    
    /* execute set operations for all mib objects in varbindings */
    if (message->pdu.error_status == ERROR_STATUS_NO_ERROR) {
        ptr = message->pdu.varbind_first_ptr;
        cur_ptr = var_index_ptr;
        i = 0;
        s8t ret;
        while (ptr) {
            i++;
            if ((ret = mib_set(cur_ptr->value, &ptr->varbind)) != ERROR_STATUS_NO_ERROR) {
                message->pdu.error_status = ret;
                message->pdu.error_index = i;
                mib_object_list_free(var_index_ptr);
                return -1;
            }
            ptr = ptr->next_ptr;
            cur_ptr = cur_ptr->next_ptr;
        }
    }
    mib_object_list_free(var_index_ptr);
    return 0;
}

/*
 *  Delegates processing of an incomming PDU to a certain application.
 */
s8t handle(message_t* message) {
    /* dispatch the PDU to the application */
    if (message->pdu.error_status == ERROR_STATUS_NO_ERROR) {
        switch (message->pdu.request_type) {
            case BER_TYPE_SNMP_GET:
                snmp_get(message);
                break;

            case BER_TYPE_SNMP_GETNEXT:
                snmp_get_next(message);
                break;

            case BER_TYPE_SNMP_SET:
                snmp_set(message);
                break;
            case BER_TYPE_SNMP_REPORT:
                return 0;
            default:
                return FAILURE;
        }
    }
    message->pdu.response_type = BER_TYPE_SNMP_RESPONSE;
    return 0;
}