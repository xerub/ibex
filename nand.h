/*
 *  ibex - nand-related stuff
 *
 *  Copyright (c) 2015 xerub
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


#ifndef NAND_H_included
#define NAND_H_included

struct bdev6_t {
    struct bdev6_t *next;
    unsigned field_4;
    unsigned field_8;
    unsigned field_C;
    unsigned field_10;
    unsigned size_lo;
    unsigned size_hi;
    int (*bdev_read)(void *bdev, void *buf, long long offset, long long size);
    unsigned block_read;
    unsigned bdev_write;
    unsigned block_write;
    unsigned field_34;
    char name[16];
} /*__attribute__((packed))*/;

struct bdev_t {
    struct bdev_t *next;
    unsigned field_4;
    unsigned field_8;
    unsigned field_C;
    unsigned field_10;
    unsigned size_lo;
    unsigned size_hi;
    unsigned field_1C;
    unsigned field_20;
    int (*bdev_read)(void *bdev, void *buf, long long offset, long long size);
    unsigned block_read;
    unsigned bdev_write;
    unsigned block_write;
    unsigned field_34;
    char name[16];
    unsigned field_48;
    unsigned field_4C;
    unsigned field_50;
    unsigned field_54;
} /*__attribute__((packed))*/;

struct firmware_image;

struct firmware_image_info {
    unsigned total_length;
    unsigned size;
    unsigned type;
    unsigned magic;
    unsigned flags;
    struct firmware_image *super;
} /*__attribute__((packed))*/;

struct firmware_image {
    struct firmware_image *prev;
    struct firmware_image *next;
    struct bdev_t *bdev;
    unsigned offset_lo;
    unsigned offset_hi;
    unsigned field_14;
    struct firmware_image_info info;
} /*__attribute__((packed))*/;


typedef unsigned int (*h2fmi_getattr_t)(int attr);
typedef int (*h2fmi_read_single_page_t)(short ce, int page, void *where, void *meta_ptr, char *ecc_out, char *ecc_ptr, int unencrypted);
typedef int (*h2fmi_read_boot_page_t)(short ce, int page, void *where);

typedef struct {
    unsigned int u0;
    h2fmi_read_single_page_t read_single_page;
    unsigned int u2;
    unsigned int u3;
    unsigned int u4;
    unsigned int u5;
    h2fmi_read_boot_page_t read_boot_page;
    unsigned int u7;
    unsigned int u8;
    unsigned int u9;
    unsigned int u10;
    unsigned int u11;
    unsigned int u12;
    unsigned int u13;
    unsigned int u14;
    unsigned int u15;
    unsigned int u16;
    unsigned int u17;
    unsigned int u18;
    unsigned int u19;
    h2fmi_getattr_t get_attr;
    /* ... */
} h2fmi_t;


int read_llb(h2fmi_read_boot_page_t read_page, int offset, int size, unsigned char *buf);
int bdev_read(void *bdev, void *buf, long long offset, long long size);
const char *bdev_name(void *bdev);

#endif
