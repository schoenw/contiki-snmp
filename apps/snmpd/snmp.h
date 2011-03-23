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

/**
 * \file
 *         SNMPv1 protocol data structure definitions.
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */

#ifndef __SNMP_H__
#define __SNMP_H__

#include "snmpd-types.h"
#include "snmpd-conf.h"

/** \brief value of the version field for the SNMPv1 */
#define SNMP_VERSION_1					0
/** \brief value of the version field for the SNMPv2c */
#define SNMP_VERSION_2C					1
/** \brief value of the version field for the SNMPv3 */
#define SNMP_VERSION_3					3

/** \brief Value of the variable binding. */
typedef union {
    /** \brief integer 32-bit value. */
    s32t            i_value;
    /** \brief unsigned integer 32-bit value. */
    u32t            u_value;
    /** \brief string value. */
    ptr_t p_value;
} varbind_value_t;

/** \brief Variable binding. */
typedef struct varbind_t {
    /** \brief a pointer to an OID. */
    ptr_t*            oid_ptr;
    /** \brief the BER type of the value. */
    u8t                 value_type;
    /** \brief value. */
    varbind_value_t     value;
} varbind_t;

/** \brief Variable binding list. */
typedef struct varbind_list_item_t {
    /** \brief variable binding. */
    varbind_t                varbind;
    /** \brief a pointer to the next element on the list. */
    struct varbind_list_item_t*   next_ptr;
} varbind_list_item_t;

/** \brief SNMP PDU. */
typedef struct {
    /** \brief type of the request. */
    u8t         request_type;
    /** \brief type of the response. */
    u8t         response_type;
    /** \brief request identifier. */
    s32t        request_id;
    /** \brief error status. */
    u8t         error_status;
    /** \brief error index. */
    u8t         error_index;
    /** \brief a list of variable bindings in the SNMP request. */
    varbind_list_item_t*  varbind_first_ptr;
    /** \brief the index of the first varbind byte in the input SNMP message. 
     * If an error occurs it's used for constructing the resulting varbind list.
     */
    u16t        varbind_index;
} pdu_t;

/** \brief SNMP message. */
typedef struct {
    /** \brief SNMP version. */
    u8t     version;
    /** \brief SNMP PDU. */
    pdu_t   pdu;

} message_t;

#if ENABLE_SNMPv3
/** \brief SNMPv3 message. */
typedef struct {
    /** \brief SNMP version. */
    u8t     version;
    /** \brief SNMP PDU. */
    pdu_t   pdu;

    /** \brief used between two SNMP entities to coordinate request messages and responses */
    u32t    msgId;
    /** \brief control processing fields of the message */
    u8t     msgFlags;

    /** \brief contextEngineID */
    ptr_t    contextEngineID;

    /** \brief contextName */
    ptr_t    contextName;
    
    /** USM security model specific parameters - msgSecurityParameters. */
    /** Should be organized into a separate data structure if more than one Security Model is supported. */

    /** \brief the snmpEngineID of the authoritative SNMP engine involved in the exchange of the message. */
    ptr_t    msgAuthoritativeEngineID;
    /** \brief the snmpEngineBoots value at the authoritative SNMP engine. */
    u32t    msgAuthoritativeEngineBoots;
    /** \brief the snmpEngineTime value at the authoritative SNMP engine. */
    u32t    msgAuthoritativeEngineTime;
    /** \brief the user (principal) on whose behalf the message is being exchanged. */
    ptr_t    msgUserName;
    ptr_t    msgAuthenticationParameters;
    ptr_t    msgPrivacyParameters;
} message_v3_t;

/** \brief reportableFlag bit in the msgFlags SNMPv3 message */
#define FLAG_REPORTABLE                               0x04
/** \brief provFlag bit in the msgFlags SNMPv3 message */
#define FLAG_PRIV                                     0x02
/** \brief authFlag bit in the msgFlags SNMPv3 message */
#define FLAG_AUTH                                     0x01

#define USM_SECURITY_MODEL                            0x03
#endif

/** \brief no error occurs while processing an SNMP request. */
#define ERROR_STATUS_NO_ERROR                           0
/** \brief the response is too big. */
#define ERROR_STATUS_TOO_BIG				1
/** \brief no the name specified in the SNMP request. */
#define ERROR_STATUS_NO_SUCH_NAME			2
/** \brief bad value. */
#define ERROR_STATUS_BAD_VALUE				3
/** \brief general error. */
#define ERROR_STATUS_READONLY				4
/** \brief general error. */
#define ERROR_STATUS_GEN_ERR				5
/** \brief wrong type. */
#define ERROR_STATUS_WRONG_TYPE				7
/** \brief not writable. */
#define ERROR_STATUS_NOT_WRITABLE        		17

#endif /* __SNMP_H__ */
