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
 *         Utility facilites for the SNMP server
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */

#ifndef __SNMPD_UTILS_H__
#define	__SNMPD_UTILS_H__

#include "snmp.h"
#include "mib.h"

/** \brief finds the minimum out of two values. */
#define min(a,b) ((a>b) ? b : a)
/** \brief finds the maximum out of two values. */
#define max(a,b) ((a>b) ? a : b)

/** \brief checks whether the pointer is 0, if so leaves the function. */
#define CHECK_PTR(ptr) if (!ptr) { snmp_log("can not allocate memory, line: %d\n", __LINE__); return -1; }
/** \brief checks whether the pointer is 0, if so leaves the function. */
#define CHECK_PTR_U(ptr) if (!ptr) { snmp_log("can not allocate memory, line: %d\n", __LINE__); return 0; }

/** \brief */
#define TRY(c) if (c < 0) { snmp_log("exception line: %d\n", __LINE__); return FAILURE; }

#define DECN(pos, value) (*pos) -= value; if (*pos < 0) { snmp_log("too big message: %d\n", __LINE__); return -1;}

#define DEC(pos) DECN(pos, 1)

/** \brief Compares two given oids.
 *  \param progmem_oid  a pointer to the oid_t structure.
 *  \param req_oid      a pointer to the oid_t structure.
  * \return 0 if two oids are equal, -1 if the first one is less, 1 otherwise.
 */
int oid_cmp(ptr_t* req_oid, ptr_t*  progmem_oid);

int oid_cmpn(ptr_t* req_oid, ptr_t*  progmem_oid, u8t len);

/** \brief Returns the length of the given oid. If the oid is stored in ROM, reads it from the ROM.
 *  \param oid      a pointer to the oid_t structure.
  * \return the length of the given oid.
 */
u16t oid_length(ptr_t* oid);

/** \brief Copies a given oid.
 *  \param dest         destination oid.
 *  \param src          source oid.
 *  \param malloc_len   the length of the buffer to allocate for the destination.
 *  \return 0 if successfully finished, otherwise -1.
 */
s8t oid_copy(ptr_t* dest, ptr_t* src, u8t malloc_len);

/** \brief Creates a new oid.
 *  \return a pointer to the oid_t structure.
 */
ptr_t* oid_create();

/** \brief Frees the memory from the oid structure.
 *  \param ptr   a pointer to the oid_t structure.
 */
void oid_free(ptr_t* ptr);

/** \brief MIB object list. Used in the processing of the SNMP SET requests. */
typedef struct mib_object_list_t
{
    /** \brief MIB object. */
    struct mib_object_t         *value;
    /** \brief a pointer to next MIB object. */
    struct mib_object_list_t    *next_ptr;
} mib_object_list_t;

/** \brief Adds an element to the MIB object list. */
mib_object_list_t* mib_object_list_append(mib_object_list_t* ptr, mib_object_t* value);

/** \brief Frees the MIB object list. */
void mib_object_list_free(mib_object_list_t* ptr);

/** \brief Adds an object to the variable binding list. */
varbind_list_item_t* varbind_list_append(varbind_list_item_t* ptr);

/** \brief creates a new variable binding */
varbind_t* varbind_create();

/** \brief Creates an MIB object. */
mib_object_t* mib_object_create();

/** \brief Releases memory from the variable bindings in a PDU. */
void free_varbinds(pdu_t* pdu);

/** \brief Releases memory from the message content. */
void free_message(message_t* message);

/** \brief Prints an array of octets in hex format. */
void print_array_as_hex (const u8t *digest, u8t len);

/** \brief Converts a 32-bit value to the first 4 octets (most significant byte first). */
void convert_2_octets(u8t* dest, u32t value);

#endif	/* __SNMPD_UTILS_H__ */

