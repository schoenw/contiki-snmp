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
 *         Defines types used in the SNMP protocol implementation.
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */

#ifndef __SNMPD_TYPES_H__
#define __SNMPD_TYPES_H__

/** \brief failure */
#define FAILURE                                        -1

/** \brief snmp version is unsupported */
#define ERR_NO_ERROR                                    0

/** \brief snmp version is unsupported */
#define ERR_UNSUPPORTED_VERSION                         1

/** \brief error code used for specifying memory allocation errors */
#define ERR_MEMORY_ALLOCATION                           2

/** \brief USM validation does not pass */
#define ERR_USM                                         3


/** \brief 8 bit usigned type */
#define u8t unsigned char
/** \brief 8 bit signed type */
#define s8t signed char
/** \brief 16 bit unsigned type */
#define u16t unsigned short
/** \brief 16 bit signed type */
#define s16t signed short
/** \brief 32 bit unsigned type */
#define u32t unsigned long
/** \brief 32 bit signed type */
#define s32t signed long

/**
 * \brief Array type.
 */
typedef struct ptr_t {
    /** \brief a pointer to an array. */
    u8t*               ptr;
    /** \brief the length of the array. */
    u16t               len;
} ptr_t;

#endif /* __SNMPD_TYPES_H__ */