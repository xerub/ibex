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


#include "plib.h"
#include "nand.h"


#define LLB_PAGE_SIZE 1536

int
read_llb(h2fmi_read_boot_page_t read_page, int offset, int size, unsigned char *buf)
{
    int rv = 0;
    int page = div(offset, LLB_PAGE_SIZE); /*offset / LLB_PAGE_SIZE*/
    int start = offset - page * LLB_PAGE_SIZE; /*offset % LLB_PAGE_SIZE*/
#if 0
    unsigned char *tmp = malloc_(4096);
    if (!tmp) {
        return -1;
    }

    for (page += 2; size > 0; page++) {
        int chunk = size;
        if (chunk > LLB_PAGE_SIZE - start) {
            chunk = LLB_PAGE_SIZE - start;
        }

        rv = read_page(0, page, tmp);
        if (rv) {
            break;
        }

        memcpy(buf, tmp + start, chunk);

        start = 0;
        buf += chunk;
        size -= chunk;
    }
#else  /* XXX more efficient, but should be used ONLY if read_page reads exactly LLB_PAGE_SIZE bytes */
    unsigned char *tmp = NULL;

    page += 2;
    if (start) {
        int chunk = LLB_PAGE_SIZE - start;
        if (!(tmp = malloc_(LLB_PAGE_SIZE))) return -1;
        rv = read_page(0, page, tmp);
        if (rv) {
            goto err;
        }
        memcpy(buf, tmp + start, chunk);
        buf += chunk;
        size -= chunk;
        page++;
    }

    for (; size >= LLB_PAGE_SIZE; page++) {
        rv = read_page(0, page, buf);
        if (rv) {
            goto err;
        }
        buf += LLB_PAGE_SIZE;
        size -= LLB_PAGE_SIZE;
    }

    if (size) {
        if (!tmp && !(tmp = malloc_(LLB_PAGE_SIZE))) return -1;
        rv = read_page(0, page, tmp);
        if (rv == 0) {
            memcpy(buf, tmp, size);
        }
    }

  err:
#endif

    free_(tmp);
    return rv;
}


int
bdev_read(void *bdev, void *buf, long long offset, long long size)
{
    if (version < 1940) {
        return ((struct bdev6_t *)bdev)->bdev_read(bdev, buf, offset, size);
    }
    return ((struct bdev_t *)bdev)->bdev_read(bdev, buf, offset, size);
}


const char *
bdev_name(void *bdev)
{
    if (version < 1940) {
        return ((struct bdev6_t *)bdev)->name;
    }
    return ((struct bdev_t *)bdev)->name;
}
