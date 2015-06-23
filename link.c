/*
 *  ibex - link external symbols
 *
 *  Copyright (c) 2010, 2015 xerub
 *  Portions Copyright (c) 2015 iH8sn0w
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


#ifndef TARGET_BASEADDR
unsigned int TARGET_BASEADDR;
#endif
#ifndef TARGET_LOADADDR
unsigned int TARGET_LOADADDR;
#endif
#ifndef TARGET_JUMPADDR
unsigned int TARGET_JUMPADDR;
#endif

int version;


#define IBOOT_LEN 0x50000
#define MASK(x, y, z) (((x) >> (y)) & ((1 << (z)) - 1))
#define MAYBE_UNUSED __attribute__((unused)) static
#define MAYBE_UNUSED_NORETURN __attribute__((unused, noreturn)) static

/* much of the code below was snarfed from iDove v3 */

MAYBE_UNUSED void* pattern_search(const void* addr, int len, int pattern, int mask, int step) {
	int i;
	char* caddr = (char*)addr;
	if (len <= 0)
		return NULL;
	if (step < 0) {
		len = -len;
		len &= ~-(step+1);
	} else {
		len &= ~(step-1);
	}
	for (i = 0; i != len; i += step) {
		int x = *(int*)(caddr + i);
		if ((x & mask) == pattern)
			return (void*)(caddr + i);
	}
	return NULL;
}

MAYBE_UNUSED void* bl_search_down(const void* start_addr, int len) {
	/* BL pattern is xx Fx xx F8+ */
	return pattern_search(start_addr, len, 0xD000F000, 0xD000F800, 2);
}

MAYBE_UNUSED void* blx_search_down(const void* start_addr, int len) {
	return pattern_search(start_addr, len, 0xC000F000, 0xD001F800, 2);
}

MAYBE_UNUSED void* bw_search_down(const void* start_addr, int len) {
	return pattern_search(start_addr, len, 0x9000F000, 0xD000F800, 2);
}

MAYBE_UNUSED void* ldr_search_down(const void* start_addr, int len) {
	/* LDR pattern is xx xx 48 xx ( 00 00 f8 00 ) */
	return pattern_search(start_addr, len, 0x00004800, 0x0000F800, 2);
}

MAYBE_UNUSED void* ldr_search_up(const void* start_addr, int len) {
	/* LDR pattern is xx xx 48 xx ( 00 00 f8 00 ) */
	return pattern_search(start_addr, len, 0x00004800, 0x0000F800, -2);
}

MAYBE_UNUSED void* ldr32_search_up(const void* start_addr, int len) {
	/* LDR32 pattern is DF F8 xx xx */
	return pattern_search(start_addr, len, 0x0000F8DF, 0x0000FFFF, -2);
}

MAYBE_UNUSED void* ldr_to(const void* loc) {
	int dw, ldr_target;
	int xref_target = (int)loc;
	int i = xref_target;
	int min_addr = xref_target - 0x420;
	for(; i > min_addr; i -= 2) {
		i = (int)ldr_search_up((void*)i, i - min_addr);
		if (i == 0) {
			return NULL;
		}
		
		dw = *(int*)i;
		ldr_target = ((i + 4) & ~3) + ((dw & 0xff) << 2);
		if (ldr_target == xref_target) {
			return (void*)i;
		}
		i -= 2;
	}
	
	i = xref_target;
	min_addr = xref_target - 0x1000;
	for(; i > min_addr; i -= 4) {
		i = (int)ldr32_search_up((void*)i, i - min_addr);
		if (i == 0) {
			break;
		}
		dw = *(int*)i;
		ldr_target = ((i + 4) & ~3) + ((dw >> 16) & 0xfff);
		if (ldr_target == xref_target) {
			return (void*)i;
		}
	}
	return NULL;
}

MAYBE_UNUSED void* push_lr_search_up(const void* start_addr, int len) {
	/* F0 B5 <-- PUSH LR */
	/* F0 BD <-- POP PC */
	return pattern_search(start_addr, len, 0x0000B580, 0x0000FF8F, -1);
}

MAYBE_UNUSED void* resolve_bl32(const void* bl) {
	int jump = 0;
	unsigned short bits = ((unsigned short *)bl)[0];
	unsigned short exts = ((unsigned short *)bl)[1];
	jump |= MASK(bits, 10, 1) << 24;
	jump |= (~(MASK(bits, 10, 1) ^ MASK(exts, 13, 1)) & 0x1) << 23;
	jump |= (~(MASK(bits, 10, 1) ^ MASK(exts, 11, 1)) & 0x1) << 22;
	jump |= MASK(bits, 0, 10) << 12;
	jump |= MASK(exts, 0, 11) << 1;
	jump |= MASK(exts, 12, 1);
	jump <<= 7;
	jump >>= 7;
	return (void*)((int)bl + 4 + jump);
}

MAYBE_UNUSED const void *
find32(const void *buffer, size_t len, unsigned int value)
{
    const unsigned int *p = (const unsigned int *)buffer;
    for (len /= 4; len--; p++) {
        if (*p == value) {
            return p;
        }
    }
    return NULL;
}

MAYBE_UNUSED const void *
find_xref(const char *pattern, size_t patlen)
{
    const unsigned char *str = boyermoore_horspool_memmem((void *)TARGET_BASEADDR, IBOOT_LEN, (void *)pattern, patlen);
    const void *ref = NULL;
    if (str) {
        ref = find32((void *)TARGET_BASEADDR, IBOOT_LEN, (unsigned int)str);
    }
    return ref;
}

MAYBE_UNUSED const void *
find_easy(const char *pattern, size_t patlen)
{
    const char *fn;
    const void *mm = find_xref(pattern, patlen);
    if (!mm) {
        return NULL;
    }
    fn = push_lr_search_up(mm, 0x200);
    if (!fn) {
        return NULL;
    }
    return fn + 1;
}

MAYBE_UNUSED printf_t
find_printf(void)
{
    const void *ldr;
    const void *bl;
    const void *mm = find_xref("jumping into image at", sizeof("jumping into image at") - 1);
    if (!mm) {
        return NULL;
    }
    ldr = ldr_to(mm);
    if (!ldr) {
        return NULL;
    }
    bl = bl_search_down(ldr, 8);
    if (!bl) {
        return NULL;
    }
    return (printf_t)(int)resolve_bl32(bl);
}

MAYBE_UNUSED snprintf_t
find_snprintf(void)
{
    const void *ldr;
    const void *bl;
    const void *mm = find_xref("CPID:", sizeof("CPID:") - 1);
    if (!mm) {
        return NULL;
    }
    ldr = ldr_to(mm);
    if (!ldr) {
        return NULL;
    }
    bl = bl_search_down(ldr, 40);
    if (!bl) {
        return NULL;
    }
    return (snprintf_t)(int)resolve_bl32(bl);
}

MAYBE_UNUSED malloc_t
find_malloc(void)
{
    return (malloc_t)(int)find_easy("_malloc must allocate at least one byte", sizeof("_malloc must allocate at least one byte") - 1);
}

MAYBE_UNUSED free_t
find_free(void)
{
    const unsigned int *pop;
    const void *mm = find_xref("heap_add_chunk", sizeof("heap_add_chunk") - 1);
    if (!mm) {
        return NULL;
    }
    pop = pattern_search(mm, 0x200, 0x40F0E8BD, 0xFFFFFFFF, -2);
    if (!pop) {
        return NULL;
    }
    return (free_t)(int)resolve_bl32(pop + 1);
}

MAYBE_UNUSED memmove_t
find_memmove(void)
{
    const void *ldr;
    const void *blx;
    const void *mm = find_xref("double panic in ", sizeof("double panic in ") - 1);
    if (!mm) {
        return NULL;
    }
    ldr = ldr_to(mm);
    if (!ldr) {
        return NULL;
    }
    blx = blx_search_down(ldr, 16);
    if (!blx) {
        return NULL;
    }
    return (memmove_t)((int)resolve_bl32(blx) & ~2);
}

MAYBE_UNUSED jumpto_t
find_jumpto(void)
{
    const void *ldr;
    const void *bl;
    const void *mm = find_xref("jumping into image at", sizeof("jumping into image at") - 1);
    if (!mm) {
        return NULL;
    }
    ldr = ldr_to(mm);
    if (!ldr) {
        return NULL;
    }
    bl = bl_search_down(ldr, 8);
    if (!bl) {
        return NULL;
    }
    bl = bl_search_down((char *)bl + 4, 16);
    if (!bl) {
        return NULL;
    }
    return (jumpto_t)(int)resolve_bl32(bl);
}

MAYBE_UNUSED aes_crypto_cmd_t
find_aes_crypto_cmd(void)
{
    return (aes_crypto_cmd_t)(int)find_easy("aes_crypto_cmd", sizeof("aes_crypto_cmd") - 1);
}

MAYBE_UNUSED enter_critical_section_t
find_enter_critical_section(void)
{
    return (enter_critical_section_t)(int)find_easy("enter_critical_section", sizeof("enter_critical_section") - 1);
}

MAYBE_UNUSED exit_critical_section_t
find_exit_critical_section(void)
{
    return (exit_critical_section_t)(int)find_easy("exit_critical_section", sizeof("exit_critical_section") - 1);
}

MAYBE_UNUSED h2fmi_select_t
find_h2fmi_select(void)
{
    const void *fn;
    const void *bl;
    const void *mm = NULL;
    const unsigned char *str = boyermoore_horspool_memmem((void *)TARGET_BASEADDR, IBOOT_LEN, (void *)"nand_syscfg", sizeof("nand_syscfg") - 1);
    if (str) {
        const char *tmp = find32((void *)TARGET_BASEADDR, IBOOT_LEN, (unsigned int)str);
        if (tmp) {
            mm = find32(tmp + 4, TARGET_BASEADDR + IBOOT_LEN - (unsigned int)tmp - 4, (unsigned int)str);
        }
    }
    if (!mm) {
        return NULL;
    }
    fn = push_lr_search_up(mm, 0x200);
    if (!fn) {
        return NULL;
    }
    bl = bl_search_down(fn, 32);
    if (!bl) {
        return NULL;
    }
    return (h2fmi_select_t)(int)resolve_bl32(bl);
}

MAYBE_UNUSED create_envvar_t
find_create_envvar(void)
{
    const void *ldr;
    const void *bl;
    const void *mm = find_xref("build-style", sizeof("build-style") - 1);
    if (!mm) {
        return NULL;
    }
    ldr = ldr_to(mm);
    if (!ldr) {
        return NULL;
    }
    bl = bl_search_down(ldr, 32);
    if (!bl) {
        return NULL;
    }
    return (create_envvar_t)(int)resolve_bl32(bl);
}

MAYBE_UNUSED fs_mount_t
find_fs_mount(void)
{
    return (fs_mount_t)(int)find_easy("fs_mount:", sizeof("fs_mount:") - 1);
}

MAYBE_UNUSED fs_loadfile_t
find_fs_loadfile(void)
{
    const char *fn;
    const void *mm = NULL;
    const unsigned char *str = boyermoore_horspool_memmem((void *)TARGET_BASEADDR, IBOOT_LEN, (void *)"Permission Denied", sizeof("Permission Denied") - 1);
    if (str) {
        const char *tmp = find32((void *)TARGET_BASEADDR, IBOOT_LEN, (unsigned int)str);
        while (tmp) {
            mm = tmp;
            tmp = find32(tmp + 4, TARGET_BASEADDR + IBOOT_LEN - (unsigned int)tmp - 4, (unsigned int)str);
        }
    }
    if (!mm) {
        return NULL;
    }
    fn = push_lr_search_up(mm, 0x200);
    if (!fn) {
        return NULL;
    }
    return (fs_loadfile_t)(int)(fn + 1);
}

MAYBE_UNUSED void *
find_bdev_stack(void)
{
    const void *bl;
    unsigned ldr;
    const void *mm = find_easy("nand_firmware", sizeof("nand_firmware") - 1);
    if (!mm) {
        mm = find_easy("nor0", sizeof("nor0") - 1);
        if (!mm) {
            return NULL;
        }
    }
    bl = bl_search_down((void *)((unsigned)mm & ~1), 16);
    if (!bl) {
        return NULL;
    }
    bl = resolve_bl32(bl);
    if (!bl) {
        return NULL;
    }
    ldr = (unsigned)ldr_search_down((void *)((unsigned)bl & ~1), 16);
    if (!ldr) {
        return NULL;
    }
    return ((void **)(ldr & ~3))[*(unsigned char *)ldr + 1];
}

MAYBE_UNUSED void *
find_image_list(void)
{
    const void *mm = find_xref("image %p: bdev %p type %c%c%c%c offset 0x%llx", sizeof("image %p: bdev %p type %c%c%c%c offset 0x%llx") - 1);
    if (!mm) {
        static struct linked_list fake_image_list;
        fake_image_list.next = fake_image_list.prev = &fake_image_list;
        return &fake_image_list;
    }
    return ((void **)mm)[-1];
}

MAYBE_UNUSED int
stub_printf(const char *fmt, ...)
{
    (void)(fmt);
    return 0;
}

MAYBE_UNUSED int
stub_snprintf(char *buf, size_t max, const char *fmt, ...)
{
    (void)(buf && max && fmt);
    printf_("unresolved snprintf\n");
    return 0;
}

MAYBE_UNUSED void *
stub_malloc(size_t n)
{
    malloc_t p = find_malloc();
    if (p) {
        malloc_ = p;
        return malloc_(n);
    }
    printf_("unresolved malloc\n");
    return NULL;
}

MAYBE_UNUSED void
stub_free(void *ptr)
{
    free_t p = find_free();
    if (p) {
        free_ = p;
        free_(ptr);
        return;
    }
    printf_("unresolved free\n");
}

MAYBE_UNUSED void *
stub_memmove(void *dst, const void *src, size_t n)
{
    memmove_t p = find_memmove();
    if (p) {
        memmove_ = p;
        return memmove_(dst, src, n);
    }
    printf_("unresolved memmove\n");
    return memmove(dst, src, n);
}

MAYBE_UNUSED_NORETURN void
stub_jumpto(int a, void *b, int c, int d)
{
    jumpto_t p = find_jumpto();
    if (p) {
        jumpto_ = p;
        jumpto_(a, b, c, d);
    }
    printf_("unresolved jumpto\n");
    _exit(0);
}

MAYBE_UNUSED int
stub_aes_crypto_cmd(int crypt_type, void *inbuf, void *outbuf, unsigned int inbuf_len, unsigned int aes_key_type, char *iv, char *key)
{
    aes_crypto_cmd_t p = find_aes_crypto_cmd();
    if (p) {
        aes_crypto_cmd_ = p;
        return aes_crypto_cmd_(crypt_type, inbuf, outbuf, inbuf_len, aes_key_type, iv, key);
    }
    printf_("unresolved aes_crypto_cmd\n");
    return -1;
}

MAYBE_UNUSED void
stub_enter_critical_section(void)
{
    enter_critical_section_t p = find_enter_critical_section();
    if (p) {
        enter_critical_section_ = p;
        enter_critical_section_();
        return;
    }
    printf_("unresolved enter_critical_section\n");
    _exit(0);
}

MAYBE_UNUSED void
stub_exit_critical_section(void)
{
    exit_critical_section_t p = find_exit_critical_section();
    if (p) {
        exit_critical_section_ = p;
        exit_critical_section_();
        return;
    }
    printf_("unresolved exit_critical_section\n");
}

MAYBE_UNUSED void *
stub_h2fmi_select(void)
{
    h2fmi_select_t p = find_h2fmi_select();
    if (p) {
        h2fmi_select_ = p;
        return h2fmi_select_();
    }
    printf_("unresolved h2fmi_select\n");
    return NULL;
}

MAYBE_UNUSED int
stub_create_envvar(const char *var, const char *val, int wtf)
{
    create_envvar_t p = find_create_envvar();
    if (p) {
        create_envvar_ = p;
        return create_envvar_(var, val, wtf);
    }
    printf_("unresolved create_envvar\n");
    return -1;
}

MAYBE_UNUSED int
stub_fs_mount(const char *partition, const char *fstype, const char *mountpoint)
{
    fs_mount_t p = find_fs_mount();
    if (p) {
        fs_mount_ = p;
        return fs_mount_(partition, fstype, mountpoint);
    }
    printf_("unresolved fs_mount\n");
    return -1;
}

MAYBE_UNUSED int
stub_fs_loadfile(const char *path, void *address, unsigned int *size)
{
    fs_loadfile_t p = find_fs_loadfile();
    if (p) {
        fs_loadfile_ = p;
        return fs_loadfile_(path, address, size);
    }
    printf_("unresolved fs_loadfile\n");
    return -1;
}

int
link(void *caller)
{
    extern char _start[];
    if (!version) {
#ifndef TARGET_BASEADDR
        TARGET_BASEADDR = (unsigned)caller & ~0xFFFFF;
#else
        (void)caller;
#endif
#ifndef TARGET_LOADADDR
        TARGET_LOADADDR = (unsigned)_start;
#else
        (void)_start;
#endif
#ifndef TARGET_JUMPADDR
        TARGET_JUMPADDR = TARGET_LOADADDR + 0x4000000;
#endif

        version = atoi((char *)TARGET_BASEADDR + 0x280 + 6);
        if (!version) {
            version = -1;
        }

#ifndef TARGET_PRINTF
        printf_ = find_printf();
        if (!printf_) {
            printf_ = stub_printf;
        }
#elif !defined(TARGET_BASEADDR)
        printf_ = TARGET_BASEADDR + TARGET_PRINTF;
#endif

#ifndef TARGET_SNPRINTF
        snprintf_ = find_snprintf();
        if (!snprintf_) {
            snprintf_ = stub_snprintf;
        }
#elif !defined(TARGET_BASEADDR)
        snprintf_ = TARGET_BASEADDR + TARGET_SNPRINTF;
#endif

#ifndef TARGET_MALLOC
        malloc_ = stub_malloc;
#elif !defined(TARGET_BASEADDR)
        malloc_ = TARGET_BASEADDR + TARGET_MALLOC;
#endif

#ifndef TARGET_FREE
        free_ = stub_free;
#elif !defined(TARGET_BASEADDR)
        free_ = TARGET_BASEADDR + TARGET_FREE;
#endif

#ifndef TARGET_MEMMOVE
        memmove_ = stub_memmove;
#elif !defined(TARGET_BASEADDR)
        memmove_ = TARGET_BASEADDR + TARGET_MEMMOVE;
#endif

#ifndef TARGET_AES_CRYPTO_CMD
        aes_crypto_cmd_ = stub_aes_crypto_cmd;
#elif !defined(TARGET_BASEADDR)
        aes_crypto_cmd_ = TARGET_BASEADDR + TARGET_AES_CRYPTO_CMD;
#endif

#ifndef TARGET_ENTER_CRITICAL_SECTION
        enter_critical_section_ = stub_enter_critical_section;
#elif !defined(TARGET_BASEADDR)
        enter_critical_section_ = TARGET_BASEADDR + TARGET_ENTER_CRITICAL_SECTION;
#endif

#ifndef TARGET_EXIT_CRITICAL_SECTION
        exit_critical_section_ = stub_exit_critical_section;
#elif !defined(TARGET_BASEADDR)
        exit_critical_section_ = TARGET_BASEADDR + TARGET_EXIT_CRITICAL_SECTION;
#endif

#ifndef TARGET_JUMPTO
        jumpto_ = stub_jumpto;
#elif !defined(TARGET_BASEADDR)
        jumpto_ = TARGET_BASEADDR + TARGET_JUMPTO;
#endif

#ifndef TARGET_H2FMI_SELECT
        h2fmi_select_ = stub_h2fmi_select;
#elif !defined(TARGET_BASEADDR)
        h2fmi_select_ = TARGET_BASEADDR + TARGET_H2FMI_SELECT;
#endif

#ifndef TARGET_CREATE_ENVVAR
        create_envvar_ = stub_create_envvar;
#elif !defined(TARGET_BASEADDR)
        create_envvar_ = TARGET_BASEADDR + TARGET_CREATE_ENVVAR;
#endif

#ifndef TARGET_FS_MOUNT
        fs_mount_ = stub_fs_mount;
#elif !defined(TARGET_BASEADDR)
        fs_mount_ = TARGET_BASEADDR + TARGET_FS_MOUNT;
#endif

#ifndef TARGET_FS_LOADFILE
        fs_loadfile_ = stub_fs_loadfile;
#elif !defined(TARGET_BASEADDR)
        fs_loadfile_ = TARGET_BASEADDR + TARGET_FS_LOADFILE;
#endif

#ifndef TARGET_BDEV_STACK
        bdev_stack = find_bdev_stack();
#elif !defined(TARGET_BASEADDR)
        bdev_stack = (void *)(TARGET_BASEADDR + TARGET_BDEV_STACK);
#endif

#ifndef TARGET_IMAGE_LIST
        image_list = find_image_list();
#elif !defined(TARGET_BASEADDR)
        image_list = (void *)(TARGET_BASEADDR + TARGET_IMAGE_LIST);
#endif
    }
    return version;
}

#ifndef TARGET_BASEADDR
#define TARGET_BASEADDR 0
#endif

#ifdef TARGET_PRINTF
printf_t printf_ = (printf_t)(TARGET_BASEADDR + TARGET_PRINTF);
#else
printf_t printf_;
#endif

#ifdef TARGET_SNPRINTF
snprintf_t snprintf_ = (snprintf_t)(TARGET_BASEADDR + TARGET_SNPRINTF);
#else
snprintf_t snprintf_;
#endif

#ifdef TARGET_MALLOC
malloc_t malloc_ = (malloc_t)(TARGET_BASEADDR + TARGET_MALLOC);
#else
malloc_t malloc_;
#endif

#ifdef TARGET_FREE
free_t free_ = (free_t)(TARGET_BASEADDR + TARGET_FREE);
#else
free_t free_;
#endif

#ifdef TARGET_MEMMOVE
memmove_t memmove_ = (memmove_t)(TARGET_BASEADDR + TARGET_MEMMOVE);
#else
memmove_t memmove_;
#endif

#ifdef TARGET_AES_CRYPTO_CMD
aes_crypto_cmd_t aes_crypto_cmd_ = (aes_crypto_cmd_t)(TARGET_BASEADDR + TARGET_AES_CRYPTO_CMD);
#else
aes_crypto_cmd_t aes_crypto_cmd_;
#endif

#ifdef TARGET_ENTER_CRITICAL_SECTION
enter_critical_section_t enter_critical_section_ = (enter_critical_section_t)(TARGET_BASEADDR + TARGET_ENTER_CRITICAL_SECTION);
#else
enter_critical_section_t enter_critical_section_;
#endif

#ifdef TARGET_EXIT_CRITICAL_SECTION
exit_critical_section_t exit_critical_section_ = (exit_critical_section_t)(TARGET_BASEADDR + TARGET_EXIT_CRITICAL_SECTION);
#else
exit_critical_section_t exit_critical_section_;
#endif

#ifdef TARGET_JUMPTO
jumpto_t jumpto_ = (jumpto_t)(TARGET_BASEADDR + TARGET_JUMPTO);
#else
jumpto_t jumpto_;
#endif

#ifdef TARGET_H2FMI_SELECT
h2fmi_select_t h2fmi_select_ = (h2fmi_select_t)(TARGET_BASEADDR + TARGET_H2FMI_SELECT);
#else
h2fmi_select_t h2fmi_select_;
#endif

#ifdef TARGET_CREATE_ENVVAR
create_envvar_t create_envvar_ = (create_envvar_t)(TARGET_BASEADDR + TARGET_CREATE_ENVVAR);
#else
create_envvar_t create_envvar_;
#endif

#ifdef TARGET_FS_MOUNT
fs_mount_t fs_mount_ = (fs_mount_t)(TARGET_BASEADDR + TARGET_FS_MOUNT);
#else
fs_mount_t fs_mount_;
#endif

#ifdef TARGET_FS_LOADFILE
fs_loadfile_t fs_loadfile_ = (fs_loadfile_t)(TARGET_BASEADDR + TARGET_FS_LOADFILE);
#else
fs_loadfile_t fs_loadfile_;
#endif

#ifdef TARGET_BDEV_STACK
void *bdev_stack = (void *)(TARGET_BASEADDR + TARGET_BDEV_STACK);
#else
void *bdev_stack;
#endif

#ifdef TARGET_IMAGE_LIST
void *image_list = (void *)(TARGET_BASEADDR + TARGET_IMAGE_LIST);
#else
void *image_list;
#endif
