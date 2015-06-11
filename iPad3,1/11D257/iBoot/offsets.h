/*
 *  ibex - target specific addresses
 *
 *  Copyright (c) 2014, 2015 xerub
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef OFFSETS_H_included
#define OFFSETS_H_included

#define TARGET_BASEADDR			0xBFF00000
#define TARGET_LOADADDR			0x80000000
#define TARGET_JUMPADDR			0x84000000

#define TARGET_PRINTF			(0x34F00 + 1)
#define TARGET_SNPRINTF			(0x354B8 + 1)
#define TARGET_MEMMOVE			(0x35990)
#define TARGET_ENTER_CRITICAL_SECTION	(0x224C0 + 1)
#define TARGET_EXIT_CRITICAL_SECTION	(0x2252C + 1)
#define TARGET_AES_CRYPTO_CMD		(0x2429C + 1)
#define TARGET_MALLOC			(0x1B814 + 1)
#define TARGET_FREE			(0x1B8C8 + 1)
#define TARGET_JUMPTO			(0x22060 + 1)
#define TARGET_H2FMI_SELECT		(0x02DCC + 1)
#define TARGET_CREATE_ENVVAR		(0x1A138 + 1)
#define TARGET_FS_MOUNT			(0x267F8 + 1)
#define TARGET_FS_LOADFILE		(0x26A44 + 1)

#define TARGET_BDEV_STACK		(0x491E8)
#define TARGET_IMAGE_LIST		(0x4640C)

#endif
