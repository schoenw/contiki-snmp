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

/**
 * \file
 *         MIB object initialization.
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */

#ifndef __MIBINIT_H__
#define	__MIBINIT_H__

#include "mib.h"

/**
 * Adds all necessary object to the MIB. Should be changed if a new object needs to be added to the MIB.
 * \brief Initializes the MIB objects.
 */
s8t mib_init();

#endif	/* __MIBINIT_H__ */

