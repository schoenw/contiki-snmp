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
 *         Defines functions for populating the MIB with objects and processing incoming SNMP requests.
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */

#ifndef __MIB_H__
#define __MIB_H__

#include "snmp.h"

/** \brief Enables static memory allocation to be used for storing the MIB.
 *         The value is the number of objects in the MIB. If not specified,
 *         dynamic memory allocation is used
 */
#define MIB_SIZE            0

/** \brief Enables MIB dynamic tables. If enabled, every MIB object uses additional 2 bytes. */
#define ENABLE_MIB_TABLE    1

/** \brief Enables program (ROM) memory for storing oids on the AVR Raven platform. */
#define ENABLE_PROGMEM      1

/** \brief MIB object type. */
typedef struct mib_object_t mib_object_t;

/** \brief Get value function type. 
 *  \param object   a pointer to the MIB object.
 *  \param oid      a BER encoded oid which is used only for tabular objects. Specifies an object in the table.
 *  \param len      the length of the oid.
 *  \return 0 if successfully finished, otherwise -1.
 */
typedef s8t(*get_value_t)(mib_object_t* object, u8t* oid, u8t len);

#if ENABLE_MIB_TABLE
/** \brief Get next oid function type.
 *  \param object   a pointer to the MIB object.
 *  \param oid      a BER encoded oid which is used only for tabular objects. Specifies an object in the table.
 *  \param len      the length of the oid.
 *  \return a pointer to oid_t with the next oid.
 */
typedef ptr_t* (*get_next_oid_t)(mib_object_t* object, u8t* oid, u8t len);
#endif

/** \brief Get value function type.
 *  \param object   a pointer to the MIB object.
 *  \param oid      a BER encoded oid which is used only for tabular objects. Specifies an object in the table.
 *  \param len      the length of the oid.
 *  \param value    value to set.
 *  \return 0 if successfully finished, otherwise -1.
 */
typedef s8t(*set_value_t)(mib_object_t* object, u8t* oid, u8t len, varbind_value_t value);

/** \brief Read-only flag. */
#define FLAG_ACCESS_READONLY     0x80

/** \brief Read-only flag. */
#define FLAG_SET_VALUE           0x40

/** \brief MIB object data structure. */
struct mib_object_t {
    /** \brief flags for the object.
     *  Bit 7 specifies the max access to the object: 0 - readonly, 1 - read-write.
     */
    u8t attrs;

    /** \brief Variable binding for the object. */
    varbind_t varbind;

    /** \brief A pointer to the get value function. */
    get_value_t get_fnc_ptr;

#if ENABLE_MIB_TABLE
    /** \brief A pointer to the get next oid function. It is set only for tabular objects. */
    get_next_oid_t get_next_oid_fnc_ptr;
#endif

    /** \brief A pointer to the set value function. */
    set_value_t set_fnc_ptr;

#if !MIB_SIZE
    /** \brief A pointer to next object in the MIB. */
    struct mib_object_t* next_ptr;
#endif
};

/** \brief Adds a scalar object to the MIB.
 *  \param oid          the oid of the object
 *  \param flags        flags assigned to the object
 *  \param value_type   type of the value of the object.
 *  \param value        initial value of the object.
 *  \param gfp          a pointer to a get value function.
 *  \param svfp         a pointer to a set value function.
 *  \return 0 if successfully finished, otherwise -1.
 */
s8t add_scalar(ptr_t* oid, u8t flags, u8t value_type, const void* const value, get_value_t gfp, set_value_t svfp);

#if ENABLE_MIB_TABLE
/** \brief Adds a tabular object to the MIB.
 *  \param oid_prefix   oid prefix of the object.
 *  \param gfp          a pointer to a get value function.
 *  \param gfp          a pointer to a get next oid function.
 *  \param svfp         a pointer to a set value function.
 *  \return 0 if successfully finished, otherwise -1.
 */
s8t add_table(ptr_t* oid_prefix, get_value_t gfp, get_next_oid_t gnofp, set_value_t svfp);
#endif

/** \brief Gets an MIB object for a given variable binding.
 *  \param req   variable binding.
 *  \return a pointer to an object if such object exists, 0 otherwise.
 */
mib_object_t* mib_get(varbind_t* req);

/** \brief Gets next MIB object for a given variable binding.
 *  \param req   variable binding.
 *  \return a pointer to an object if such object exists, 0 otherwise.
 */
mib_object_t* mib_get_next(varbind_t* req);

/** \brief Sets the value of the given MIB object
 *  \param object   an MIB object.
 *  \param req      a variable binding with the value that should be set.
 *  \return 0 if successfully finished, error code otherwise.
 */
s8t mib_set(mib_object_t* object, varbind_t* req);

#endif /* __MIB_H__ */
