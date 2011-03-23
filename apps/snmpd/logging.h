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
 *         Provides logging facilites for the JacobsSNMP.
 * \author
 *         Siarhei Kuryla <kurilo@gmail.com>
 */

#ifndef __SNMPD_LOGGING_H__
#define __SNMPD_LOGGING_H__

/** \brief indicates whether debug is enabled */
#define DEBUG 0

/** \brief indicates whether info messages are enabled */
#define INFO 0


#if DEBUG
/**
 * Adds a message to the log with the DEBUG level. Enabled if the DEBUG macro definition is set to 1.
 * \brief Logs message with the DEBUG level.
 * \param format A pointer to a string containing the format of the message.
 * \param ... arguments for formating the message.
 * \hideinitializer
 */
void snmp_log(char* format, ...);
#else
#define snmp_log(...)
#endif /* DEBUG */

#if INFO
/**
 * Adds a message to the log with the INFO level. Enabled if the INFO macro definition is set to 1.
 * \brief Logs message with the INFO level.
 * \param format A pointer to a string containing the format of the message.
 * \param ... arguments for formating the message.
 * \hideinitializer
 */
void snmp_info(char* format, ...);
#else
#define snmp_info(...)
#endif /* INFO */


#endif /* __SNMPD_LOGGING_H__ */
