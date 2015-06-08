/*
 *  ibex - payload
 *
 *  Copyright (c) 2010, 2014-2015 xerub
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
#include "blob.h"


#define TRANSFER_CHUNK 1000


static void
hex2str(char *str, int buflen, const unsigned char *buf)
{
    static const char h2a[] = "0123456789abcdef";
    for (; buflen > 0; --buflen) {
        unsigned char byte = *buf++;
        *str++ = h2a[byte >> 4];
        *str++ = h2a[byte & 0xF];
    }
    *str = '\0';
}


static int
str2hex(int buflen, unsigned char *buf, const char *str)
{
    unsigned char *ptr = buf;
    int seq = -1;
    while (buflen > 0) {
        int nibble = *str++;
        if (nibble >= '0' && nibble <= '9') {
            nibble -= '0';
        } else {
            nibble |= 0x20;
            if (nibble >= 'a' && nibble <= 'f') {
                nibble -= 'a' - 10;
            } else {
                break;
            }
        }
        if (seq >= 0) {
            *buf++ = (seq << 4) | nibble;
            buflen--;
            seq = -1;
        } else {
            seq = nibble;
        }
    }
    return buf - ptr;
}


unsigned int get_addr = 0;
unsigned int get_endp = 0x1000;
static char get_buf[TRANSFER_CHUNK * 2 + 16];


int
_main(int argc, CmdArg *argv)
{
    if (!link(__builtin_return_address(0))) {
        return 0;
    }

    if (argc == 4 && argv[1].string[0] == 'r') {
        /* cmd r addr size */
        unsigned int addr = argv[2].inthex;
        unsigned int size = argv[3].inthex;
        printf_("d:");
        while (size--) {
            printf_(" %02x", *(unsigned char *)addr);
            addr++;
        }
        printf_("\n");
        return 0;
    }

    if (argc >= 4 && argv[1].string[0] == 'w') {
        /* cmd w addr val val val... */
        int i;
        unsigned int addr = argv[2].inthex;
        for (i = 3; i < argc; i++, addr++) {
            unsigned char val = argv[i].inthex;
            printf_("[%x] = %02x\n", addr, val);
            *(unsigned char *)addr = val;
        }
        flush_icache();
        return 0;
    }

    if (argc >= 3 && argv[1].string[0] == 'x') {
        /* cmd x addr val val val... */
        int i, j;
        unsigned int r[8];
        unsigned int addr = argv[2].inthex;
        for (j = 0, i = 3; i < argc && j < 8; i++, j++) {
            r[j] = argv[i].inthex;
        }
        while (j < 8) {
            r[j++] = 0;
        }
        printf_("-> %x\n", ((int (*)())addr)(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]));
        return 0;
    }

    if (argc == 5 && argv[1].string[0] == 'a') {
        /* cmd a enc/dec uid/gid data */
        int mode = (argv[2].string[0] == 'e') ? AES_ENCRYPT : AES_DECRYPT;
        int type = (argv[3].string[0] == 'u') ? UID_KEY : GID_KEY;
        unsigned char tmpbuf[KBAG_KEY_IV_SIZE];
        unsigned char outbuf[KBAG_KEY_IV_SIZE];
        char strbuf[KBAG_KEY_IV_SIZE * 2 + 1];
        int buflen = str2hex(sizeof(tmpbuf), tmpbuf, argv[4].string);
        aes_crypto_cmd_(mode, (void *)tmpbuf, (void *)outbuf, buflen, type, NULL, NULL);
        hex2str(strbuf, buflen, outbuf);
        printf_("out: %s\n", strbuf);
        return 0;
    }

    /* --- Transfer function --- */

    if (argc >= 2 && argv[1].string[0] == 'g') {
        /* cmd g [addr [endp]] */
        if (argc > 2) {
            get_addr = argv[2].inthex;
            get_endp = get_addr + 0x1000;
            if (argc > 3) {
                get_endp = argv[3].inthex;
                if (get_endp < get_addr) {
                    get_endp = get_addr + 0x1000;
                }
            }
        }

        if (get_addr < get_endp) {
            int i, chunk = get_endp - get_addr;
            if (chunk > TRANSFER_CHUNK) {
                chunk = TRANSFER_CHUNK;
            }
            i = snprintf_(get_buf, 16, "%u:%x:", chunk, get_addr);
            if (i) {
                hex2str(get_buf + i - 1, chunk, (void *)get_addr);
                if (create_envvar_("cmd-results", get_buf, 0) == 0) {
                    get_addr += chunk;
                    return 0;
                }
            }
        }

        create_envvar_("cmd-results", "end-of-transmission", 0);
        printf_("end-of-transmission\n");
        return 0;
    }

    /* --- blob functions --- */

    if (argc == 2 && argv[1].string[0] == 'b') {
        return save_all_blobs();
    }

    printf_("bad args\n");
    return 0;
}
