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

#define TARGET_BASEADDR			0x9FF00000
#define TARGET_LOADADDR			0x80000000
#define TARGET_JUMPADDR			0x84000000

#define TARGET_PRINTF			(0x32E7C + 1)
#define TARGET_SNPRINTF			(0x33434 + 1)
#define TARGET_MEMMOVE			(0x3390C)
#define TARGET_ENTER_CRITICAL_SECTION	(0x20324 + 1)
#define TARGET_EXIT_CRITICAL_SECTION	(0x20390 + 1)
#define TARGET_AES_CRYPTO_CMD		(0x22210 + 1)
#define TARGET_MALLOC			(0x196D8 + 1)
#define TARGET_FREE			(0x1978C + 1)
#define TARGET_JUMPTO			(0x1FF40 + 1)
#define TARGET_H2FMI_SELECT		(0x2DB8 + 1)
#define TARGET_CREATE_ENVVAR		(0x17FFC + 1)
#define TARGET_FS_MOUNT			(0x24768 + 1)
#define TARGET_FS_LOADFILE		(0x249B4 + 1)

#define TARGET_BDEV_STACK		(0x46088)
#define TARGET_IMAGE_LIST		(0x43460)

#endif
