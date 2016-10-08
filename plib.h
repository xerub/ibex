/*
 *  ibex - pseudo-library
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


#ifndef PLIB_H_included
#define PLIB_H_included

#include <stdarg.h>
#include <stddef.h>
#include <offsets.h>

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

#define AES_ENCRYPT		0x10
#define AES_DECRYPT		0x11

#define KBAG_IV_SIZE		0x10
#define KBAG_KEY_SIZE		0x20
#define KBAG_KEY_IV_SIZE	(KBAG_IV_SIZE + KBAG_KEY_SIZE)

#define SHSH_KEY		0x100
#define GID_KEY			0x20000200
#define UID_KEY			0x20000201

struct linked_list {
    struct linked_list *prev;
    struct linked_list *next;
};

typedef struct CmdArg {
    signed int integer;		/* strtol(str, 0, 0) */
    unsigned int uinteger;	/* strtoul(str, 0, 0) */
    signed int inthex;		/* strtol(str, 0, 16) */
    unsigned char boolean;	/* evaluated from "true", "false" or CmdArg.integer */
    char *string __attribute__((aligned(4)));
} CmdArg;

#ifndef TARGET_BASEADDR
extern unsigned int TARGET_BASEADDR;
#endif
#ifndef TARGET_LOADADDR
extern unsigned int TARGET_LOADADDR;
#endif
#ifndef TARGET_JUMPADDR
extern unsigned int TARGET_JUMPADDR;
#endif

extern int version;

typedef int (*printf_t)(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
extern printf_t printf_;

typedef int (*snprintf_t)(char *buf, size_t max, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
extern snprintf_t snprintf_;

typedef void *(*malloc_t)(size_t size);
extern malloc_t malloc_;

typedef void (*free_t)(void *ptr);
extern free_t free_;

typedef void *(*memmove_t)(void *dst, const void *src, size_t n);
extern memmove_t memmove_;

typedef int (*aes_crypto_cmd_t)(int crypt_type, void *inbuf, void *outbuf, unsigned int inbuf_len, unsigned int aes_key_type, char *key, char *iv);
extern aes_crypto_cmd_t aes_crypto_cmd_;

typedef void (*enter_critical_section_t)(void);
extern enter_critical_section_t enter_critical_section_;

typedef void (*exit_critical_section_t)(void);
extern exit_critical_section_t exit_critical_section_;

typedef void (*jumpto_t)(int, void *, int, int) __attribute__((noreturn));
extern jumpto_t jumpto_;

typedef void *(*h2fmi_select_t)(void);
extern h2fmi_select_t h2fmi_select_;

typedef int (*create_envvar_t)(const char *var, const char *val, int wtf);
extern create_envvar_t create_envvar_;

typedef int (*fs_mount_t)(const char *partition, const char *fstype, const char *mountpoint);
extern fs_mount_t fs_mount_;

typedef int (*fs_loadfile_t)(const char* path, void *address, unsigned int *size);
extern fs_loadfile_t fs_loadfile_;

extern void *bdev_stack;
extern void *image_list;

/* our stuff */

extern unsigned int get_addr;
extern unsigned int get_endp;

int link(void *caller);

void flush_icache(void);

/* misc C stuff */

unsigned div(unsigned N, unsigned D);

unsigned char *
boyermoore_horspool_memmem(const unsigned char* haystack, size_t hlen,
                           const unsigned char* needle,   size_t nlen);

int xtoi(const char *hptr);

/* standard C stuff */

int atoi(const char *nptr);

int strcmp(const char *s1, const char *s2);
int memcmp(const void *b1, const void *b2, size_t len);
void *memset(void *s, int c, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memcpy(void *dest, const void *src, size_t n);
void *memmem(const void* haystack, size_t hlen, const void* needle, size_t nlen);

void _exit(int status) __attribute__((noreturn));

#endif
