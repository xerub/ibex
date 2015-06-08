/*
 *  ibex - blob stuff
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
#include "blob.h"


struct img3_root {
    unsigned int magic;
    unsigned int size;
    unsigned int dataSize;
    unsigned int shshOffset;
    unsigned int name;
};


int
decrypt_shsh(void *rsa)
{
    static const unsigned char shshkey[] = { 0xDB, 0x1F, 0x5B, 0x33, 0x60, 0x6C, 0x5F, 0x1C, 0x19, 0x34, 0xAA, 0x66, 0x58, 0x9C, 0x06, 0x61 };
    static unsigned char shshbuf[sizeof(shshkey)];
    static int beentheredonethat = 0;
    int rv;
    if (!beentheredonethat) {
        rv = aes_crypto_cmd_(AES_ENCRYPT, (char *)shshkey, shshbuf, KBAG_IV_SIZE, SHSH_KEY, NULL, NULL);
        if (rv) {
            return -1;
        }
        beentheredonethat = 1;
    }
    rv = aes_crypto_cmd_(AES_DECRYPT, rsa, rsa, 0x80, 0, (char *)shshbuf, NULL);
    if (rv) {
        return -1;
    }
    return 0;
}


/* XXX is h2fmi structure stable? XXX does not require the nand_llb patch ABOVE nand_firmware_init() */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmultichar"
static struct blob_t *
save_llb(void)
{
    int rv;
    struct blob_t *llb;
    struct img3_root root;
    unsigned int *shsh;
    unsigned int sz;
    h2fmi_t *p = h2fmi_select_();

    if (!p || !p->read_boot_page) {
        printf_("h2fmi err\n");
        return NULL;
    }
    rv = read_llb(p->read_boot_page, 0, sizeof(root), (void *)&root);
    if (rv) {
        printf_("llb read err1\n");
        return NULL;
    }

    if (!root.shshOffset || root.shshOffset >= root.dataSize) {
        printf_("bad shsh offset\n");
        return NULL;
    }
    sz = root.dataSize - root.shshOffset + 64;
    llb = malloc_(offsetof(struct blob_t, data) + sz);
    if (!llb) {
        printf_("out of memory\n");
        return NULL;
    }
    rv = read_llb(p->read_boot_page, root.shshOffset + 20 - 64, sz, llb->data);
    if (rv) {
        printf_("llb read err2\n");
        free_(llb);
        return NULL;
    }
    shsh = (unsigned int *)(llb->data + 64);
    if (*shsh != 'SHSH') {
        printf_("bad signature\n");
        free_(llb);
        return NULL;
    }

    rv = decrypt_shsh(shsh + 3);
    if (rv) {
        printf_("aes err\n");
        free_(llb);
        return NULL;
    }

    llb->type = 'illb';
    llb->size = sz;
    return llb;
}

static struct blob_t *
save_krnl(void)
{
    struct blob_t *blob;
    struct img3_root *root;
    unsigned int size;
    char *addr = (char *)TARGET_LOADADDR + 0x1000000;

    /* load kernel, iH8sn0w style */
    fs_mount_("nand0a", "hfs", "/boot");
    if ((size = 0x3000000, fs_loadfile_("/boot/System/Library/Caches/com.apple.kernelcaches/kernelcache", addr, &size)) &&
        (size = 0x3000000, fs_loadfile_("/boot/System/Library/Caches/com.apple.kernelcaches/kernelcache.s5l8920x", addr, &size)) &&
        (size = 0x3000000, fs_loadfile_("/boot/System/Library/Caches/com.apple.kernelcaches/kernelcache.s5l8922x", addr, &size)) &&
        (size = 0x3000000, fs_loadfile_("/boot/System/Library/Caches/com.apple.kernelcaches/kernelcache.s5l8720x", addr, &size))) {
        printf_("kernel read err1\n");
        return NULL;
    }

    root = (struct img3_root *)addr;
    if (!root->shshOffset || root->shshOffset >= root->dataSize) {
        return NULL;
    }
    blob = malloc_(sizeof(struct blob_t));
    if (!blob) {
        printf_("out of memory\n");
        return NULL;
    }
    if (root->shshOffset + 20 + 12 + 0x80 > size) {
        printf_("kernel read err2\n");
        free_(blob);
        return NULL;
    }
    memcpy(blob->data, addr + root->shshOffset + 20 + 12, 0x80);
    if (decrypt_shsh(blob->data)) {
        printf_("aes err\n");
        free_(blob);
        return NULL;
    }
    blob->type = 'krnl';
    blob->size = 0x80;
    return blob;
}

static struct blob_t *
save_ticket(struct firmware_image *e)
{
    struct blob_t *ticket;
    unsigned int tmp[16];
    unsigned int result;
    result = bdev_read(e->bdev, tmp, e->offset_lo, sizeof(tmp));
    if (result != sizeof(tmp)) {
        printf_("ticket read err1\n");
        return NULL;
    }
    ticket = malloc_(offsetof(struct blob_t, data) + tmp[15]);
    if (!ticket) {
        printf_("out of memory\n");
        return NULL;
    }
    result = bdev_read(e->bdev, ticket->data, e->offset_lo + sizeof(tmp), tmp[15]);
    if (result != tmp[15]) {
        free_(ticket);
        printf_("ticket read err2\n");
        return NULL;
    }
    ticket->type = e->info.type;
    ticket->size = result;
    return ticket;
}

static struct blob_t *
save_blob(struct firmware_image *e)
{
    struct blob_t *blob;
    struct img3_root root;
    unsigned int result;
    if (e->info.type == 'SCAB') {
        return save_ticket(e);
    }
    result = bdev_read(e->bdev, &root, e->offset_lo, sizeof(root));
    if (result != sizeof(root)) {
        printf_("image read err1\n");
        return NULL;
    }
    if (!root.shshOffset || root.shshOffset >= root.dataSize) {
        return NULL;
    }
    blob = malloc_(sizeof(struct blob_t));
    if (!blob) {
        printf_("out of memory\n");
        return NULL;
    }
    result = bdev_read(e->bdev, blob->data, e->offset_lo + root.shshOffset + 20 + 12, 0x80);
    if (result != 0x80) {
        free_(blob);
        printf_("image read err2\n");
        return NULL;
    }
    if (decrypt_shsh(blob->data)) {
        free_(blob);
        printf_("aes err\n");
        return NULL;
    }
    blob->type = e->info.type;
    blob->size = 0x80;
    return blob;
}
#pragma GCC diagnostic pop

int
save_all_blobs(void)
{
    unsigned i, n;
    unsigned int total;
    unsigned char *data;
    struct blob_t *blobs[16];
    struct firmware_image *e;

    for (n = 0, e = ((struct firmware_image *)image_list)->next; n < ARRAY_SIZE(blobs) - 2 && e != image_list; e = e->next, n++) {
        /*printf_("saving blob for %c%c%c%c\n",
                (e->info.type >> 24) & 0xFF,
                (e->info.type >> 16) & 0xFF,
                (e->info.type >> 8) & 0xFF,
                e->info.type & 0xFF);*/
        blobs[n] = save_blob(e);
    }
    blobs[n++] = save_llb();
    blobs[n++] = save_krnl();

    for (total = 0, i = 0; i < n; i++) {
        if (blobs[i]) {
            total += blobs[i]->size + offsetof(struct blob_t, data);
        }
    }

    data = malloc_(total);
    if (!data) {
        printf_("out of memory\n");
        while (n-- > 0) {
            if (blobs[n]) {
                free_(blobs[n]);
            }
        }
        return 0;
    }

    for (total = 0, i = 0; i < n; i++) {
        if (blobs[i]) {
            unsigned size = blobs[i]->size + offsetof(struct blob_t, data);
            memcpy(data + total, blobs[i], size);
            total += size;
            free_(blobs[i]);
        }
    }

    get_addr = (unsigned)data;
    get_endp = get_addr + total;
    printf_("Blobs copied at %x - %x\n", get_addr, get_endp);
    return 0;
}
